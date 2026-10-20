/* redirect.c — cgroup-eBPF TCP redirector untuk Android.
 *
 * SELF-CONTAINED: tidak butuh header kernel sistem sama sekali.
 * Compile: clang -O2 -g -target bpf -c redirect.c -o redirect.bpf.o
 *
 * Arsitektur (v2 — tanpa getsockopt):
 *   1. cgroup/connect4 & connect6: intersep TCP connect() dari aplikasi,
 *      simpan tujuan asli di pending_map (key = socket cookie), lalu
 *      belokkan tujuan ke 127.0.0.1:<redir_port>.
 *   2. sockops (BPF_SOCK_OPS_TCP_CONNECT_CB): saat koneksi terbentuk,
 *      pindahkan entri dari pending_map ke port_map dengan key =
 *      source port klien (local_port). Source port ini BISA dibaca
 *      userspace dari accepted socket via getpeername().
 *   3. Userspace (sing-box, via cilium/ebpf): saat accept di redir-port,
 *      baca source port klien -> lookup port_map -> dapat tujuan asli.
 *      Tidak perlu memalsukan SO_ORIGINAL_DST sama sekali.
 *
 * Yang dilewat (bypass):
 *   - UID 0 (root): sing-box & loader jalan sebagai root, cegah loop.
 *   - 127.0.0.0/8 dan ::1: cegah loop lokal.
 *   - Non-TCP: hanya TCP yang ditangani.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/* ---- tipe dasar ---- */
typedef unsigned char  __u8;
typedef unsigned short __u16;
typedef unsigned int   __u32;
typedef unsigned long long __u64;
typedef signed char  __s8;
typedef short __s16;
typedef int   __s32;
typedef long long __s64;

/* ---- macro definisi map & section (ala libbpf, tanpa header) ---- */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[1]
#define SEC(name) __attribute__((section(name), used))
#define __bpf_md_ptr(type, name) \
	union { type name; __u64 :64; } __attribute__((aligned(8)))
#define __always_inline inline __attribute__((always_inline))

/* ---- konstanta ---- */
#define BPF_MAP_TYPE_HASH     1
#define BPF_MAP_TYPE_ARRAY    2
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_ANY 0

#define IPPROTO_TCP 6
#define AF_INET  2
#define AF_INET6 10

/* BPF_SOCK_OPS op codes (linux/bpf.h) */
#define BPF_SOCK_OPS_TCP_CONNECT_CB 3

/* ---- deklarasi helper BPF (nomor fungsi dari linux/bpf.h) ---- */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key,
				   const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)15;
static __u64 (*bpf_get_socket_cookie)(void *ctx) = (void *)46;

#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)

/* ---- struct konteks kernel (layout persis linux/bpf.h) ---- */
struct bpf_sock; /* opaque, hanya dipakai sebagai pointer */

struct bpf_sock_addr {
	__u32 user_family;
	__u32 user_ip4;
	__u32 user_ip6[4];
	__u32 user_port;
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 msg_src_ip4;
	__u32 msg_src_ip6[4];
	__bpf_md_ptr(struct bpf_sock *, sk);
};

/* Minimal struct bpf_sock_ops — hanya sampai remote_port.
 * Offset harus persis kernel: op@0, args[4]@4, family@20,
 * remote_ip4@24, local_ip4@28, remote_ip6@32, local_ip6@48,
 * local_port@64, remote_port@68. */
struct bpf_sock_ops {
	__u32 op;
	__u32 args[4];
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 local_port;   /* HOST byte order */
	__u32 remote_port;  /* HOST byte order */
};

/* ---- data ---- */

/* Tujuan asli yang disimpan.
 * Layout dibuat agar addr 4-byte aligned (verifier menolak akses
 * misaligned ke stack). */
struct orig_dst {
	__u32 addr[4];  /* IPv4: addr[0] saja; IPv6: semua 16 byte */
	__u16 port;     /* network byte order */
	__u8  family;   /* AF_INET=2 atau AF_INET6=10 */
	__u8  pad;
};

/* Sementara: key = socket cookie, diisi saat connect,
 * dipindah ke port_map saat TCP_CONNECT_CB. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct orig_dst);
} pending_map SEC(".maps");

/* Final: key = source port klien (HOST byte order, __u32).
 * Userspace lookup pakai port dari getpeername() accepted socket. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, struct orig_dst);
} port_map SEC(".maps");

/* Port redir tujuan (HOST byte order), diisi loader via map update. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u16);
} cfg_port SEC(".maps");

/* ---- program ---- */

static __always_inline int redir_port(void)
{
	__u32 key = 0;
	__u16 *p = bpf_map_lookup_elem(&cfg_port, &key);
	if (!p || *p == 0)
		return 0;
	return *p;
}

static __always_inline int is_loopback4(__u32 daddr)
{
	/* daddr network order; oktet pertama = byte terendah di LE. */
	return (daddr & 0xff) == 0x7f;
}

SEC("cgroup/connect4")
int cg_connect4(struct bpf_sock_addr *ctx)
{
	struct orig_dst orig = {};
	__u64 cookie;
	int rport;

	if (ctx->protocol != IPPROTO_TCP)
		return 1;

	/* Lewati root (sing-box & loader) agar tidak loop. */
	if ((bpf_get_current_uid_gid() & 0xffffffff) == 0)
		return 1;

	if (is_loopback4(ctx->user_ip4))
		return 1;

	cookie = bpf_get_socket_cookie(ctx);
	if (!cookie)
		return 1;

	rport = redir_port();
	if (!rport)
		return 1; /* belum dikonfigurasi; lewatkan saja */

	orig.family = AF_INET;
	orig.port = ctx->user_port; /* sudah network byte order */
	orig.addr[0] = ctx->user_ip4;
	bpf_map_update_elem(&pending_map, &cookie, &orig, BPF_ANY);

	/* Belokkan ke 127.0.0.1:<rport> */
	ctx->user_ip4 = 0x0100007f; /* 127.0.0.1 network order */
	ctx->user_port = bpf_htons((__u16)rport);

	return 1;
}

SEC("cgroup/connect6")
int cg_connect6(struct bpf_sock_addr *ctx)
{
	struct orig_dst orig = {};
	__u64 cookie;
	__u32 a0, a1, a2, a3;
	int rport;

	if (ctx->protocol != IPPROTO_TCP)
		return 1;

	if ((bpf_get_current_uid_gid() & 0xffffffff) == 0)
		return 1;

	/* Baca SEMUA field ctx dulu ke lokal, sebelum ada write apa pun. */
	a0 = ctx->user_ip6[0];
	a1 = ctx->user_ip6[1];
	a2 = ctx->user_ip6[2];
	a3 = ctx->user_ip6[3];

	/* Lewati ::1 */
	if (a0 == 0 && a1 == 0 && a2 == 0 && a3 == bpf_htonl(1))
		return 1;

	cookie = bpf_get_socket_cookie(ctx);
	if (!cookie)
		return 1;

	rport = redir_port();
	if (!rport)
		return 1;

	orig.family = AF_INET6;
	orig.port = ctx->user_port;
	/* Salin manual field-per-field; hindari memcpy/aritmetika ptr dari ctx. */
	orig.addr[0] = a0;
	orig.addr[1] = a1;
	orig.addr[2] = a2;
	orig.addr[3] = a3;
	bpf_map_update_elem(&pending_map, &cookie, &orig, BPF_ANY);

	/* Baru sekarang write ke ctx, di akhir. */
	ctx->user_ip6[0] = 0;
	ctx->user_ip6[1] = 0;
	ctx->user_ip6[2] = 0;
	ctx->user_ip6[3] = bpf_htonl(1); /* ::1 */
	ctx->user_port = bpf_htons((__u16)rport);

	return 1;
}

SEC("sockops")
int ebpf_sockops(struct bpf_sock_ops *ctx)
{
	struct orig_dst *orig;
	__u64 cookie;
	__u32 sport;

	if (ctx->op != BPF_SOCK_OPS_TCP_CONNECT_CB)
		return 0;

	/* Hanya yang menuju redir (sudah dibelokkan connect hook). */
	cookie = bpf_get_socket_cookie(ctx);
	if (!cookie)
		return 0;

	orig = bpf_map_lookup_elem(&pending_map, &cookie);
	if (!orig)
		return 0; /* bukan koneksi redirect kita */

	sport = ctx->local_port; /* HOST byte order */
	if (sport == 0)
		return 0;

	bpf_map_update_elem(&port_map, &sport, orig, BPF_ANY);
	bpf_map_delete_elem(&pending_map, &cookie);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";

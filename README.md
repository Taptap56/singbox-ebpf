# singbox-ebpf-cgroup-kit

Inbound **eBPF cgroup** untuk **sing-box resmi v1.14.3** (versi dikunci) —
penangkap trafik **TCP lokal (HP sendiri)**, dengan format & arsitektur
yang sama persis seperti kit `ebpf-cgroup-kit` untuk mihomo:

| Isi | Fungsi |
| --- | --- |
| `new-files/protocol/ebpfcgroup/inbound.go` | Inbound baru `"ebpf-cgroup"` (pola sama seperti inbound `redirect` bawaan) |
| `new-files/protocol/ebpfcgroup/cgroup_linux.go` | Loader eBPF (cilium/ebpf) |
| `new-files/protocol/ebpfcgroup/cgroup_other.go` | Stub non-Linux |
| `new-files/protocol/ebpfcgroup/ebpf/redirect.c` | Program BPF: `cgroup/connect4` + `connect6` + `sockops` |
| `ebpfcgroup.patch` | Daftarkan inbound di `include/registry.go` |
| `apply-ebpf-cgroup.sh` | Pasang semua di atas ke source sing-box |
| `.github/workflows/build-android-arm64.yml` | Build otomatis di GitHub Actions |

## Cara kerja

1. Program BPF di hook `cgroup/connect4` & `connect6` mengintersep
   `connect()` TCP aplikasi, mencatat tujuan asli di `pending_map`
   (key = socket cookie), lalu membelokkan tujuan ke
   `127.0.0.1:<listen_port>` inbound ini.
2. Program `sockops` (`BPF_SOCK_OPS_TCP_CONNECT_CB`) memindahkan entri ke
   `port_map` dengan key = source port klien.
3. Inbound menerima koneksi, membaca tujuan asli dari `port_map`
   (fallback: `SO_ORIGINAL_DST`, jadi koneksi dari iptables REDIRECT
   juga tetap jalan), lalu menyerahkan koneksi ke router sing-box.

Yang dilewatkan (bypass): UID 0/root (termasuk sing-box sendiri, anti
loop), loopback 127.0.0.0/8 & ::1, dan semua non-TCP.

**Attach anti-EPERM (Android 15):** netd memasang program placeholder
pass-through di hook connect root cgroup secara single-program, sehingga
attach MULTI & `BPF_LINK_CREATE` ditolak EPERM. Loader kit ini mencoba
flags berurutan **[0, OVERRIDE, MULTI]** — flags `0` menggantikan
placeholder netd, persis trik yang dipakai sing-ebpf (fork CHIZI).

## Batasan (sama seperti kit mihomo)

- **Hanya TCP, hanya trafik lokal.** UDP dan klien hotspot tidak lewat
  cgroup — pasangkan dengan inbound `tproxy` untuk keduanya
  (arsitektur 2 komponen, sama seperti rancangan kit mihomo).
- **Wajib root** (attach eBPF) dan kernel `CONFIG_CGROUP_BPF=y`
  (terverifikasi ada di HP fleur via `/proc/config.gz`).
- Ini jalur **alternatif** dari inbound `ebpf` bawaan fork CHIZI:
  kelebihannya basis sing-box **resmi** v1.14.3 (tidak tergantung fork
  orang) dan kode penangkapnya milik sendiri; kekurangannya cakupan
  lebih sempit (TCP lokal saja, tanpa mode shared/TC bawaan).

## Build via GitHub Actions (disarankan)

1. Siapkan repo berisi source sing-box **v1.14.3**:
   - fork `SagerNet/sing-box`, lalu buat branch dari tag `v1.14.3`; atau
   - buat repo baru dan upload snapshot source v1.14.3.
2. Taruh **semua isi folder kit ini** di root repo (termasuk
   `.github/workflows/build-android-arm64.yml`), commit & push.
3. Tab **Actions** → *Build sing-box android-arm64 + ebpf-cgroup
   (v1.14.3)* → **Run workflow**.
4. Ambil binary `sing-box` dari **Artifacts**
   (`sing-box-android-arm64-ebpfcgroup-1.14.3`).

Workflow menjalankan: apply kit → `go get github.com/cilium/ebpf@v0.16.0`
→ compile BPF dengan clang → `make build VERSION=1.14.3` dengan
`TAGS=with_quic,with_dhcp,with_utls,with_clash_api,with_wireguard`
(CGO + NDK r29, pola sama seperti build CHIZI yang sudah terbukti —
hasilnya `sing-box version 1.14.3`).

## Build manual

```sh
# di root source sing-box v1.14.3, isi kit sudah di root juga
./apply-ebpf-cgroup.sh
go get github.com/cilium/ebpf@v0.16.0 && go mod tidy
clang -O2 -target bpf -c protocol/ebpfcgroup/ebpf/redirect.c \
  -o protocol/ebpfcgroup/ebpf/redirect.bpf.o
export TAGS=with_quic,with_dhcp,with_utls,with_clash_api,with_wireguard
make build VERSION=1.14.3   # sesuaikan CC/GOOS/GOARCH untuk Android
```

## Config

Tambahkan inbound ini ke `inbounds` config sing-box:

```json
{
  "type": "ebpf-cgroup",
  "tag": "ebpf-cgroup-in",
  "listen": "127.0.0.1",
  "listen_port": 15361
}
```

Opsi tambahan: `"cgroup_path": "/sys/fs/cgroup"` (default persis itu;
jarang perlu diubah). `listen_port` wajib diisi — port ini yang jadi
tujuan belokan BPF, dan inbound listen di situ.

Contoh pasangan lengkap (lokal via eBPF + UDP/hotspot via tproxy):

```json
"inbounds": [
  { "type": "ebpf-cgroup", "tag": "ebpf-cgroup-in",
    "listen": "127.0.0.1", "listen_port": 15361 },
  { "type": "tproxy", "tag": "tproxy-in",
    "listen": "127.0.0.1", "listen_port": 15362, "network": ["udp"] }
]
```

(tproxy tetap butuh aturan iptables fwmark/route seperti biasa;
ebpf-cgroup tidak memasang aturan iptables apa pun.)

## Catatan

- `sing-box check` memvalidasi config termasuk tipe inbound baru ini
  (inbound dibuat saat box dibuat) — `listen_port` kosong langsung
  ditolak dengan pesan jelas.
- Bila attach gagal total (semua flags ditolak), sing-box gagal start
  dengan error `ebpf-cgroup: attach ...` — tidak ada mode diam-diam
  jalan tanpa tangkapan.
- File `redirect.bpf.o` **tidak** disertakan di kit; selalu dicompile
  dari `redirect.c` saat build (oleh workflow / langkah manual di atas).

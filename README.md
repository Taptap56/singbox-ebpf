# singbox-ebpf-cgroup-kit

Kit eBPF untuk **sing-box resmi** (versi dipilih saat Run workflow,
**tanpa fork** — repo ini isinya kit saja, workflow mengambil source
resminya sendiri).
Isinya DUA inbound eBPF:

1. **`"ebpf"` — jalur eBPF PENUH ala fork CHIZI-0618** (hasil porting
   `CHIZI-0618/sing-box` + library `CHIZI-0618/sing-ebpf` ke basis resmi): trafik **lokal TCP+UDP** lewat cgroup, **klien hotspot**
   lewat TC di interface AP, DNS hijack, bypass alamat privat, filter
   UID/paket Android, FakeIP ICMP reply. Skema config **persis** config
   fork CHIZI (`local:`/`shared:`) — config yang jalan di binary CHIZI
   bisa dipakai apa adanya di sini.
2. **`"ebpf-cgroup"` — inbound ringan buatan kit ini** (TCP lokal saja,
   pola sama seperti kit `ebpf-cgroup-kit` untuk mihomo).

| Isi | Fungsi |
| --- | --- |
| `new-files/protocol/ebpf/` (35 file) | Inbound `"ebpf"` penuh (porting CHIZI) |
| `new-files/protocol/ebpfcgroup/` | Inbound `"ebpf-cgroup"` + loader + `ebpf/redirect.c` |
| `new-files/option/ebpf.go` | Skema opsi `local`/`shared` (persis CHIZI) |
| `new-files/adapter/ebpf.go`, `new-files/include/ebpf*.go` | Tipe diagnostik + registrasi (gerbang tag `with_ebpf`) |
| `new-files/route/network_ebpf*.go`, `new-files/common/dialer/ebpf_self_bypass*.go`, `new-files/common/udpio/`, `new-files/common/listener/socket_buffer_*.go`, `new-files/common/process/searcher_ebpf_linux.go`, `new-files/dns/transport/fakeip/store_ebpf.go` | Glue: self-bypass soket sing-box sendiri, batch UDP, info proses |
| `ebpfcgroup.patch` | Registrasi 2 inbound + glue kecil di `constant`, `box.go`, `route`, `common/dialer`, `common/listener` (10 file, ±343 baris) |
| `apply-ebpf-cgroup.sh` | Pasang semua di atas ke source sing-box |
| `.github/workflows/build-android-arm64.yml` | Build otomatis di GitHub Actions |

Datapath eBPF-nya sendiri (program BPF cgroup/TC, loader, penanganan
placeholder netd Android 15) berasal dari library
**`github.com/CHIZI-0618/sing-ebpf` v0.1.0-alpha.13** yang diambil
workflow/`go get` saat build — objek BPF-nya sudah ter-compile di dalam
library itu, tidak perlu compile BPF terpisah untuk inbound `"ebpf"`.

## Cara kerja inbound `"ebpf"` (ringkas)

- **Local (HP sendiri):** program BPF di hook cgroup socket-address
  (`connect4/6`, `sendmsg4/6`, `recvmsg4/6`) membelokkan trafik TCP &
  UDP aplikasi ke listener internal inbound; tujuan asli dilacak per
  soket. Soket milik sing-box sendiri didaftarkan sebagai *self-bypass*
  (disiapkan `box.go` → `dialer.PrepareEBPFSelfBypass`) supaya tidak
  meng-loop tangkapannya sendiri.
- **Shared (hotspot):** program TC di interface AP (mis. `wlan1`)
  menangkap trafik klien hotspot (TCP+UDP, mode `socket_assign` /
  `packet_rewrite`).
- **DNS:** `dns_mode: "hijack"` mengintersep query DNS di kedua jalur.
- **Attach anti-EPERM (Android 15):** netd memasang placeholder
  pass-through single-program di hook cgroup root — library sing-ebpf
  menggantikannya secara aman (query dulu, pulihkan saat detach), sama
  seperti build CHIZI yang terbukti jalan.

## Config

Persis config fork CHIZI — contoh (yang terverifikasi lolos
`sing-box check` di binary kit ini):

```json
{
  "type": "ebpf",
  "tag": "ebpf-in",
  "network": ["tcp", "udp"],
  "local": {
    "enabled": true,
    "dns_mode": "hijack",
    "bypass_private_address": true
  },
  "shared": {
    "enabled": true,
    "dns_mode": "hijack",
    "interface": ["wlan1"],
    "bypass_private_address": true
  }
}
```

Opsi lengkap (filter UID/paket, `data_plane`, `udp_timeout`,
`fakeip_icmp`, dll.) sama dengan dokumentasi inbound ebpf di repo
CHIZI-0618/sing-box (`docs/configuration/inbound/ebpf.md`).

Inbound `"ebpf-cgroup"` (TCP lokal saja) tetap tersedia:

```json
{ "type": "ebpf-cgroup", "tag": "ebpf-cgroup-in",
  "listen": "127.0.0.1", "listen_port": 15361 }
```

## Build via GitHub Actions (disarankan)

Repo-nya cukup berisi **kit ini saja** (seperti repo
`fauermeuar/singbox-1.14.3`) — source sing-box versi pilihan diambil
otomatis oleh workflow dari `SagerNet/sing-box`:

1. Taruh **semua isi folder kit ini** di root repo (termasuk
   `.github/workflows/build-android-arm64.yml`), commit & push.
2. Tab **Actions** → *Build sing-box android-arm64 + ebpf-cgroup* →
   **Run workflow** → pilih `latest` (deteksi rilis stabil terbaru
   **saat workflow jalan**, seperti TaptapApp yang cek GitHub tiap
   dibuka) atau pilih versi dari daftar 20 stabil terbaru, atau isi
   versi kustom (mis. `1.15.0-alpha.13`) → **Run workflow**.
   Versi kustom menang bila diisi; versi yang dipilih divalidasi
   tag-nya di awal (gagal cepat bila tag tidak ada).

   Catatan: dropdown GitHub Actions tidak bisa dinamis — daftar 20 itu
   snapshot saat kit dibuat. Yang selalu segar adalah `latest`; daftar
   lama tetap bisa dipilih selama tag-nya ada.
3. Ambil binary `sing-box` dari **Artifacts**
   (`sing-box-android-arm64-ebpfcgroup-<versi>`).

Workflow menjalankan: tentukan versi (termasuk deteksi `latest`) +
validasi tag → checkout source resmi tag `v<versi>` → apply kit →
`go get github.com/CHIZI-0618/sing-ebpf@v0.1.0-alpha.13` → compile BPF
ebpf-cgroup dengan clang → `make build VERSION=<versi>` dengan
`TAGS=with_quic,with_dhcp,with_utls,with_clash_api,with_wireguard,with_ebpf`
(CGO + NDK r29 — hasilnya `sing-box version <versi>`). Go yang dipakai
mengikuti `go.mod` versi yang dipilih (otomatis, tanpa setting manual).

Tanpa tag `with_ebpf`, inbound `"ebpf"` tetap terdaftar tapi menolak
jalan dengan pesan `eBPF inbound is not included in this build`
(aman untuk build biasa).

## Build manual

```sh
# di root source sing-box (versi pilihanmu), isi kit sudah dicopy ke sana juga
./apply-ebpf-cgroup.sh
go get github.com/CHIZI-0618/sing-ebpf@v0.1.0-alpha.13
clang -O2 -target bpf -c protocol/ebpfcgroup/ebpf/redirect.c \
  -o protocol/ebpfcgroup/ebpf/redirect.bpf.o
export TAGS=with_quic,with_dhcp,with_utls,with_clash_api,with_wireguard,with_ebpf
CGO_ENABLED=1 GOOS=android GOARCH=arm64 \
  CC=<NDK>/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang \
  make build VERSION=<versi pilihan>
```

## Status & batasan

- **Terverifikasi lokal (2026-10-20):** kit ter-apply bersih di clone
  murni v1.14.3; build Linux **dan** Android/arm64 lolos;
  `sing-box check` untuk config skema CHIZI (tipe `ebpf`) **dan**
  config `ebpf-cgroup` sama-sama exit 0. Tes runtime di HP (attach
  BPF sungguhan) belum dilakukan untuk build kit ini — kode
  datapath-nya identik dengan build CHIZI yang sudah terbukti jalan
  di HP yang sama.
- **Pilih versi:** patch dibuat terhadap v1.14.3 — versi jauh lebih baru
  bisa gagal `git apply` bila file yang dipatch berubah di upstream;
  itu sinyal patch perlu di-rebase, bukan bug workflow. Versi yang
  dipilih divalidasi tag-nya di awal (gagal cepat bila tag tidak ada).
- **Wajib root** (attach eBPF) dan kernel `CONFIG_CGROUP_BPF=y`.
- Yang **tidak** ikut di-porting dari fork CHIZI: API/diagnostik eBPF
  untuk daemon & perintah CLI tambahan (tidak ngaruh ke datapath).
- **Kredit & lisensi:** inbound `"ebpf"` + library sing-ebpf karya
  **CHIZI-0618** (GPLv3, sama seperti sing-box). Kit ini cuma
  memindahkannya ke basis resmi.

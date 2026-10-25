#!/bin/sh
# apply-ebpf-cgroup.sh — pasang kit eBPF ke source sing-box (versi pilihan workflow):
#   - inbound "ebpf-cgroup" (buatan kit ini, TCP lokal saja)
#   - inbound "ebpf" PENUH ala fork CHIZI-0618 (local TCP+UDP + shared
#     hotspot, DNS hijack) — hasil porting ke basis resmi
# Jalankan dari ROOT source sing-box (versi apa pun yang dipilih), dengan seluruh isi kit juga
# di sana (workflow mencopy script ini + patch + new-files/ ke root source).
set -e
cd "$(dirname "$0")"

if [ ! -f include/registry.go ] || [ ! -f go.mod ]; then
  echo "ERROR: jalankan di root source sing-box (include/registry.go tidak ditemukan)." >&2
  exit 1
fi

echo "== copy package inbound baru =="
cp -r new-files/protocol/ebpfcgroup protocol/
cp -r new-files/protocol/ebpf protocol/
echo "   protocol/ebpfcgroup/ + protocol/ebpf/ OK"

echo "== copy file pendukung inbound ebpf penuh =="
mkdir -p common/udpio dns/transport/fakeip
cp new-files/option/ebpf.go option/
cp new-files/adapter/ebpf.go adapter/
cp new-files/include/ebpf.go new-files/include/ebpf_stub.go include/
cp new-files/route/network_ebpf.go new-files/route/network_ebpf_stub.go route/
cp new-files/common/dialer/ebpf_self_bypass_linux.go new-files/common/dialer/ebpf_self_bypass_stub.go common/dialer/
cp new-files/common/udpio/*.go common/udpio/
cp new-files/common/listener/socket_buffer_bsd.go new-files/common/listener/socket_buffer_other.go common/listener/
cp new-files/common/process/searcher_ebpf_linux.go common/process/
cp new-files/dns/transport/fakeip/store_ebpf.go dns/transport/fakeip/
echo "   option/adapter/include/route/dialer/udpio/listener/process/fakeip OK"

echo "== apply patch (registrasi + glue) =="
git apply --check ebpfcgroup.patch && git apply ebpfcgroup.patch
echo "   registry, constant, box, route, dialer, listener OK"

echo ""
echo "SELESAI. Langkah lanjut:"
echo "  1. Tambah library eBPF CHIZI: go get github.com/CHIZI-0618/sing-ebpf@v0.1.0-alpha.13"
echo "  2. Compile BPF ebpf-cgroup: clang -O2 -target bpf -c protocol/ebpfcgroup/ebpf/redirect.c -o protocol/ebpfcgroup/ebpf/redirect.bpf.o"
echo "     (Objek BPF inbound ebpf penuh sudah termasuk di dalam modul sing-ebpf.)"
echo "  3. Build: make build VERSION=<versi pilihan> dengan TAGS menyertakan with_ebpf (lihat README)"
echo "  (Atau pakai workflow GitHub Actions di kit ini — otomatis.)"

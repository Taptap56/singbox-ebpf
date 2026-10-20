#!/bin/sh
# apply-ebpf-cgroup.sh — pasang inbound ebpf-cgroup ke source sing-box v1.14.3.
# Jalankan dari ROOT repo sing-box (snapshot/fork v1.14.3), dengan seluruh
# isi kit ini juga di root repo (sejajar dengan script ini).
#
# Isi kit ini:
#   new-files/protocol/ebpfcgroup/  -> copy ke protocol/ebpfcgroup/
#   ebpfcgroup.patch                -> git apply ke include/registry.go
set -e
cd "$(dirname "$0")"

if [ ! -f include/registry.go ] || [ ! -f go.mod ]; then
  echo "ERROR: jalankan di root source sing-box (include/registry.go tidak ditemukan)." >&2
  exit 1
fi

echo "== copy file baru =="
mkdir -p protocol/ebpfcgroup/ebpf
cp -r new-files/protocol/ebpfcgroup/* protocol/ebpfcgroup/
echo "   protocol/ebpfcgroup/{inbound.go,cgroup_linux.go,cgroup_other.go,ebpf/redirect.c}"

echo "== apply patch registry =="
git apply --check ebpfcgroup.patch && git apply ebpfcgroup.patch
echo "   include/registry.go OK (inbound \"ebpf-cgroup\" terdaftar)"

echo ""
echo "SELESAI. Langkah lanjut:"
echo "  1. Tambah dependensi loader: go get github.com/cilium/ebpf@v0.16.0"
echo "  2. Compile BPF: clang -O2 -target bpf -c protocol/ebpfcgroup/ebpf/redirect.c -o protocol/ebpfcgroup/ebpf/redirect.bpf.o"
echo "  3. Build: make build VERSION=1.14.3 (TAGS sesuai kebutuhan, lihat README)"
echo "  (Atau pakai workflow GitHub Actions di kit ini — otomatis.)"

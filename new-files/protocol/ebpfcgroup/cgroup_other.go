//go:build !linux

package ebpfcgroup

import (
	"errors"
	"net/netip"
)

// Config mirrors the Linux config for API compatibility.
type Config struct {
	RedirPort  uint16
	CgroupPath string
}

// Manager is a stub on non-Linux platforms.
type Manager struct{}

// startManager always fails on non-Linux: cgroup-eBPF requires Linux.
func startManager(Config) (*Manager, error) {
	return nil, errors.New("ebpf-cgroup requires Linux")
}

// lookupPort never finds anything on non-Linux.
func (m *Manager) lookupPort(uint16) (netip.AddrPort, bool) {
	return netip.AddrPort{}, false
}

// Close is a no-op on non-Linux.
func (m *Manager) Close() error { return nil }

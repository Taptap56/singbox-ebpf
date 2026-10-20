//go:build linux

package ebpfcgroup

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

//go:embed ebpf/redirect.bpf.o
var bpfObject []byte

// Config is the runtime configuration for the redirector.
type Config struct {
	RedirPort  uint16 // port listen inbound ini; koneksi dibelokkan ke sini
	CgroupPath string // default /sys/fs/cgroup
}

// origDst mirrors struct orig_dst in redirect.c (BPF side).
type origDst struct {
	Addr   [4]uint32
	Port   uint16 // network byte order
	Family uint8
	Pad    uint8
}

// Manager owns the cgroup-eBPF redirector lifecycle. Close detaches
// every program and releases the collection; it is safe to call twice.
type Manager struct {
	coll     *ebpf.Collection
	cgroupFd int
	attached []attachedProg
}

type attachedProg struct {
	prog       *ebpf.Program
	attachType uint32
}

// BPF syscall commands and attach types (linux/bpf.h).
const (
	bpfProgAttach = 8
	bpfProgDetach = 9

	bpfCgroupSockOps      = 3
	bpfCgroupInet4Connect = 10
	bpfCgroupInet6Connect = 11

	bpfFAllowMulti    = 2
	bpfFAllowOverride = 1
)

// bpfProgAttachAttr mirrors struct bpf_attr for BPF_PROG_ATTACH/DETACH.
type bpfProgAttachAttr struct {
	TargetFd    uint32
	AttachBpfFd uint32
	AttachType  uint32
	AttachFlags uint32
	_           [48]byte
}

// startManager loads the BPF programs, configures the redirect port, and
// attaches connect4/connect6/sockops hooks to the cgroup hierarchy.
//
// Catatan Android 15: netd memasang program placeholder pass-through di
// hook connect4/6 root cgroup (single-program, tanpa flags), sehingga
// attach MULTI dan BPF_LINK_CREATE ditolak EPERM. Karena itu attach di
// sini mencoba flags berurutan [0, OVERRIDE, MULTI] — flags 0 menggantikan
// placeholder netd persis seperti yang dilakukan sing-ebpf (fork CHIZI).
func startManager(cfg Config) (m *Manager, err error) {
	if cfg.RedirPort == 0 {
		return nil, errors.New("ebpf-cgroup requires a non-zero listen_port")
	}
	cgroupPath := cfg.CgroupPath
	if cgroupPath == "" {
		cgroupPath = "/sys/fs/cgroup"
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil {
		return nil, fmt.Errorf("ebpf-cgroup: load BPF spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("ebpf-cgroup: create BPF collection: %w", err)
	}
	m = &Manager{coll: coll}
	defer func() {
		if err != nil && m != nil {
			_ = m.Close()
		}
	}()

	// Publish the redirect port to the BPF side (host byte order).
	cfgMap := coll.Maps["cfg_port"]
	if cfgMap == nil {
		return nil, errors.New("ebpf-cgroup: BPF map cfg_port not found")
	}
	var key uint32
	if err := cfgMap.Put(key, cfg.RedirPort); err != nil {
		return nil, fmt.Errorf("ebpf-cgroup: set redir port: %w", err)
	}

	attachments := []struct {
		progName   string
		attachType uint32
	}{
		{"cg_connect4", bpfCgroupInet4Connect},
		{"cg_connect6", bpfCgroupInet6Connect},
		{"ebpf_sockops", bpfCgroupSockOps},
	}

	// Open cgroup FD once for all attachments.
	cgroupFd, err := unix.Open(cgroupPath, unix.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("ebpf-cgroup: open cgroup %s: %w", cgroupPath, err)
	}
	m.cgroupFd = cgroupFd

	for _, a := range attachments {
		prog := coll.Programs[a.progName]
		if prog == nil {
			return nil, fmt.Errorf("ebpf-cgroup: BPF program %s not found", a.progName)
		}
		var lastErr error
		attached := false
		for _, flags := range []uint32{0, bpfFAllowOverride, bpfFAllowMulti} {
			if err := progAttachFlags(cgroupFd, prog.FD(), a.attachType, flags); err != nil {
				lastErr = err
				continue
			}
			attached = true
			break
		}
		if !attached {
			return nil, fmt.Errorf("ebpf-cgroup: attach %s to %s: %w (semua flags gagal)", a.progName, cgroupPath, lastErr)
		}
		m.attached = append(m.attached, attachedProg{prog: prog, attachType: a.attachType})
	}

	return m, nil
}

// progAttachFlags performs BPF_PROG_ATTACH with explicit flags.
func progAttachFlags(cgroupFd int, progFd int, attachType uint32, flags uint32) error {
	attr := bpfProgAttachAttr{
		TargetFd:    uint32(cgroupFd),
		AttachBpfFd: uint32(progFd),
		AttachType:  attachType,
		AttachFlags: flags,
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, bpfProgAttach,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return errno
	}
	return nil
}

// progDetach performs BPF_PROG_DETACH.
func progDetach(cgroupFd int, progFd int, attachType uint32) error {
	attr := bpfProgAttachAttr{
		TargetFd:    uint32(cgroupFd),
		AttachBpfFd: uint32(progFd),
		AttachType:  attachType,
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, bpfProgDetach,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return errno
	}
	return nil
}

// lookupPort reads the original destination for a client source port
// from the BPF port_map. The bool reports whether an entry was found.
func (m *Manager) lookupPort(clientPort uint16) (netip.AddrPort, bool) {
	if m == nil || m.coll == nil {
		return netip.AddrPort{}, false
	}
	portMap := m.coll.Maps["port_map"]
	if portMap == nil {
		return netip.AddrPort{}, false
	}
	var val origDst
	key := uint32(clientPort)
	// Retry sebentar: sock_ops di klien jalan sangat cepat setelah
	// handshake, tapi scheduling bisa bikin map belum terisi.
	for i := 0; i < 5; i++ {
		if err := portMap.Lookup(key, &val); err == nil {
			return val.toAddrPort(), true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return netip.AddrPort{}, false
}

// toAddrPort converts the BPF orig_dst to a netip.AddrPort.
func (o *origDst) toAddrPort() netip.AddrPort {
	port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&o.Port))[:])
	switch o.Family {
	case 2: // AF_INET
		var b4 [4]byte
		binary.BigEndian.PutUint32(b4[:], o.Addr[0])
		return netip.AddrPortFrom(netip.AddrFrom4(b4), port)
	case 10: // AF_INET6
		var b16 [16]byte
		for i := 0; i < 4; i++ {
			binary.BigEndian.PutUint32(b16[i*4:], o.Addr[i])
		}
		return netip.AddrPortFrom(netip.AddrFrom16(b16), port)
	default:
		return netip.AddrPort{}
	}
}

// Close detaches all programs and releases BPF resources.
func (m *Manager) Close() error {
	var firstErr error
	for _, a := range m.attached {
		if err := progDetach(m.cgroupFd, a.prog.FD(), a.attachType); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	m.attached = nil
	if m.cgroupFd > 0 {
		_ = unix.Close(m.cgroupFd)
		m.cgroupFd = 0
	}
	if m.coll != nil {
		m.coll.Close()
		m.coll = nil
	}
	return firstErr
}

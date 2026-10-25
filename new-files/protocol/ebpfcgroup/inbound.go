// Package ebpfcgroup menyediakan inbound "ebpf-cgroup" untuk sing-box:
// penangkap trafik TCP lokal (HP sendiri) berbasis eBPF cgroup, dengan
// format & arsitektur yang sama seperti kit ebpf-cgroup untuk mihomo.
//
// Cara kerja:
//   - Program BPF cgroup/connect4+connect6 membelokkan connect() TCP
//     aplikasi ke 127.0.0.1:<listen_port> inbound ini, sambil mencatat
//     tujuan asli di BPF map (pending_map -> port_map via sockops).
//   - Inbound ini menerima koneksi yang dibelokkan, membaca tujuan asli
//     dari port_map berdasarkan source port klien, lalu menyerahkan
//     koneksi ke router sing-box seperti inbound redirect biasa.
//   - Fallback: bila port_map tidak punya entri (mis. koneksi datang
//     dari iptables REDIRECT), tujuan asli dibaca via SO_ORIGINAL_DST.
//
// Batasan (sama seperti kit mihomo):
//   - Hanya TCP, hanya trafik lokal. UDP & klien hotspot TIDAK ditangkap
//     di sini — pasangkan dengan inbound tproxy untuk keduanya.
//   - Wajib root (attach eBPF) & kernel CONFIG_CGROUP_BPF=y.
//   - Trafik UID 0 (root — termasuk sing-box sendiri) dilewatkan agar
//     tidak loop.
package ebpfcgroup

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// TypeName adalah nama tipe inbound di config JSON: "ebpf-cgroup".
const TypeName = "ebpf-cgroup"

// RegisterInbound mendaftarkan inbound ini ke registry sing-box.
// Dipanggil dari include/registry.go (lihat ebpfcgroup.patch).
func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[InboundOptions](registry, TypeName, NewInbound)
}

// InboundOptions adalah opsi config untuk inbound ebpf-cgroup.
type InboundOptions struct {
	option.ListenOptions
	// CgroupPath adalah path cgroup v2 tempat program BPF dipasang.
	// Kosong = /sys/fs/cgroup (root hierarchy; mencakup semua aplikasi).
	CgroupPath string `json:"cgroup_path,omitempty"`
}

// Inbound adalah implementasi inbound ebpf-cgroup.
type Inbound struct {
	inbound.Adapter
	router   adapter.Router
	logger   log.ContextLogger
	listener *listener.Listener
	options  InboundOptions
	manager  *Manager
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options InboundOptions) (adapter.Inbound, error) {
	if options.ListenPort == 0 {
		return nil, errors.New("ebpf-cgroup: listen_port is required")
	}
	in := &Inbound{
		Adapter: inbound.NewAdapter(TypeName, tag),
		router:  router,
		logger:  logger,
		options: options,
	}
	in.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: in,
	})
	return in, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if err := h.listener.Start(); err != nil {
		return err
	}
	scope.Add(h.listener.Close)
	mgr, err := startManager(Config{
		RedirPort:  h.options.ListenPort,
		CgroupPath: h.options.CgroupPath,
	})
	if err != nil {
		return err
	}
	h.manager = mgr
	scope.Add(mgr.Close)
	cgroupPath := h.options.CgroupPath
	if cgroupPath == "" {
		cgroupPath = "/sys/fs/cgroup"
	}
	h.logger.Info("ebpf-cgroup attached: cgroup ", cgroupPath, ", listen_port ", h.options.ListenPort)
	return nil
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	destination, err := h.originalDestination(conn)
	if err != nil {
		conn.Close()
		h.logger.ErrorContext(ctx, "process connection from ", conn.RemoteAddr(), ": get original destination: ", err)
		return
	}
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.Destination = M.SocksaddrFromNetIP(destination)
	h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

// originalDestination mencari tujuan asli koneksi: pertama dari BPF
// port_map (koneksi yang dibelokkan eBPF cgroup), fallback ke
// SO_ORIGINAL_DST (koneksi dari iptables REDIRECT/TPROXY).
func (h *Inbound) originalDestination(conn net.Conn) (destination netip.AddrPort, err error) {
	if h.manager != nil {
		if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok && tcpAddr.Port > 0 {
			if dst, found := h.manager.lookupPort(uint16(tcpAddr.Port)); found {
				return dst, nil
			}
		}
	}
	return control.GetOriginalDestination(conn)
}

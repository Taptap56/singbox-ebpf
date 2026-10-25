package listener

import (
	"syscall"

	"github.com/sagernet/sing/common/control"
	N "github.com/sagernet/sing/common/network"
)

// UDPSocketBuffer — pengganti control.UDPSocketBuffer yang DIHAPUS dari
// sing baru (sing-box 1.14.4 memakai sing 20261023 tanpa socket_buffer.go).
// Perilaku persis implementasi lama: hanya untuk UDP, set buffer lewat
// setSocketBuffer (per-platform, file socket_buffer_func_*).
func UDPSocketBuffer(size int) control.Func {
	return func(network, address string, conn syscall.RawConn) error {
		if N.NetworkName(network) != N.NetworkUDP {
			return nil
		}
		return control.Raw(conn, func(fd uintptr) error {
			setSocketBuffer(fd, size)
			return nil
		})
	}
}

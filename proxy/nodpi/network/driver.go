package network

import (
	"io"
	"net"

	"github.com/mdlayher/packet"
	"golang.org/x/sys/unix"
)

type Driver struct {
	iface *net.Interface
	conn  *packet.Conn
}

func NewDriver() (*Driver, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, newError("failed to get interfaces").Base(err)
	}
	if len(ifaces) == 0 {
		return nil, newError("no available network interfaces")
	}
	errors := make([]error, 0)
	for _, iface := range ifaces {
		if len(iface.HardwareAddr) == 6 && iface.Flags&(net.FlagUp|net.FlagMulticast|net.FlagBroadcast) != 0 {
			conn, err := packet.Listen(&iface, packet.Datagram, unix.ETH_P_IP, nil)
			if err == nil {
				return &Driver{
					iface: &iface,
					conn:  conn,
				}, nil
			}
			errors = append(errors, err)
		}
	}
	return nil, newError("all interfaces failed", ifaces, errors)
}

func (d *Driver) Close() error {
	return d.conn.Close()
}

func (d *Driver) Write(b []byte) (int, error) {
	panic("not implemented")
}

func (d *Driver) Read(buf []byte) (int, error) {
	panic("not implemented")
}

var _ io.ReadWriteCloser = (*Driver)(nil)

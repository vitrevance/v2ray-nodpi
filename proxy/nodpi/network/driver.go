package network

import (
	"io"
	"net"

	"github.com/mdlayher/packet"
)

type Driver struct {
	iface  *net.Interface
	conn   *packet.Conn
	ip     net.IP
	DstMAC net.HardwareAddr
}

func (d *Driver) Close() error {
	return d.conn.Close()
}

func (d *Driver) Write(b []byte) (int, error) {
	dst := &packet.Addr{HardwareAddr: d.DstMAC}
	return d.conn.WriteTo(b, dst)
}

func (d *Driver) WriteTo(b []byte, mac net.HardwareAddr) (int, error) {
	dst := &packet.Addr{HardwareAddr: mac}
	return d.conn.WriteTo(b, dst)
}

func (d *Driver) Read(buf []byte) (int, error) {
	n, mac, err := d.conn.ReadFrom(buf)
	_ = mac
	return n, err
}

var _ io.ReadWriteCloser = (*Driver)(nil)

package nodpi

import (
	"context"
	"net"
	"time"

	"github.com/google/gopacket"
	vnet "github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"github.com/vitrevance/v2ray-nodpi/proxy/nodpi/network"
)

type TCPConn interface {
	net.Conn
	Send(opts gopacket.SerializeOptions, ls ...gopacket.SerializableLayer) error
}

type TCPDialer interface {
	Dial(context.Context, *net.TCPAddr) (TCPConn, error)
	Close() error
}

var _ TCPDialer = (*tcpDialer)(nil)

type tcpDialer struct {
	tcp *network.TCP
}

// Close implements TCPDialer.
func (t *tcpDialer) Close() error {
	return t.tcp.Close()
}

// Dial implements TCPDialer.
func (t *tcpDialer) Dial(ctx context.Context, addr *net.TCPAddr) (TCPConn, error) {
	return t.tcp.Dial(ctx, addr)
}

type dialerAdapter struct {
	d internet.Dialer
}

type connAdapter struct {
	conn internet.Connection
}

// Close implements TCPConn.
func (c connAdapter) Close() error {
	return c.conn.Close()
}

// LocalAddr implements TCPConn.
func (c connAdapter) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// Read implements TCPConn.
func (c connAdapter) Read(b []byte) (n int, err error) {
	return c.conn.Read(b)
}

// RemoteAddr implements TCPConn.
func (c connAdapter) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// Send implements TCPConn.
func (c connAdapter) Send(opts gopacket.SerializeOptions, ls ...gopacket.SerializableLayer) error {
	return newError("cant send on default TCP stack")
}

// SetDeadline implements TCPConn.
func (c connAdapter) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline implements TCPConn.
func (c connAdapter) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements TCPConn.
func (c connAdapter) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// Write implements TCPConn.
func (c connAdapter) Write(b []byte) (n int, err error) {
	return c.conn.Write(b)
}

// Close implements TCPDialer.
func (d *dialerAdapter) Close() error {
	return nil
}

// Dial implements TCPDialer.
func (d *dialerAdapter) Dial(ctx context.Context, addr *net.TCPAddr) (TCPConn, error) {
	conn, err := d.d.Dial(ctx, vnet.TCPDestination(vnet.IPAddress(addr.IP), vnet.Port(addr.Port)))
	if conn != nil {
		return connAdapter{conn: conn}, err
	}
	return nil, err
}

var _ TCPDialer = (*dialerAdapter)(nil)

func WrapTCPDialer(d internet.Dialer) TCPDialer {
	return &dialerAdapter{d: d}
}

func NewTCPDialer() (TCPDialer, error) {
	driver, err := network.NewDriver()
	if err != nil {
		return nil, err
	}
	stack, err := network.NewTCP(driver)
	if err != nil {
		driver.Close()
		return nil, err
	}
	return &tcpDialer{tcp: stack}, nil
}

package nodpi

import (
	"context"
	"net"

	"github.com/google/gopacket/layers"
	vnet "github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"github.com/vitrevance/v2ray-nodpi/proxy/nodpi/network"
)

type RawOption = func(*layers.IPv4, *layers.TCP) error

type TCPConn interface{ net.Conn }

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

// Close implements TCPDialer.
func (d *dialerAdapter) Close() error {
	return nil
}

// Dial implements TCPDialer.
func (d *dialerAdapter) Dial(ctx context.Context, addr *net.TCPAddr) (TCPConn, error) {
	conn, err := d.d.Dial(ctx, vnet.TCPDestination(vnet.IPAddress(addr.IP), vnet.Port(addr.Port)))
	if conn != nil {
		return conn, err
	}
	return nil, err
}

var _ TCPDialer = (*dialerAdapter)(nil)

func WrapTCPDialer(d internet.Dialer) TCPDialer {
	return &dialerAdapter{d: d}
}

func NewTCPDialer(driver *network.Driver) (TCPDialer, error) {
	stack, err := network.NewTCP(driver)
	if err != nil {
		driver.Close()
		return nil, err
	}
	return &tcpDialer{tcp: stack}, nil
}

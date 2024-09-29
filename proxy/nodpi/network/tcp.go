package network

import (
	"context"
	"math/rand"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/vitrevance/v2ray-nodpi/pkg/syncmap"
	"gvisor.dev/gvisor/pkg/tcpip/ports"
)

type TCP struct {
	driver  *Driver
	pm      *ports.PortManager
	rnd     *rand.Rand
	localIP net.IP
	router  syncmap.SyncMap[int, *conn]
	writer  chan []byte
	ctx     context.Context
	cancel  func()
}

type Payload []byte

func NewTCP(driver *Driver) (*TCP, error) {
	stack := &TCP{
		driver: driver,
		pm:     ports.NewPortManager(),
		rnd:    rand.New(rand.NewSource(0)),
	}

	stack.ctx, stack.cancel = context.WithCancel(context.Background())

	go stack.send()
	go stack.recv()

	return stack, nil
}

func (d *TCP) Close() error {
	d.cancel()
	return d.driver.Close()
}

func (d *TCP) Dial(addr *net.TCPAddr) (*conn, error) {
	p, err := d.pm.ReservePort(d.rnd, ports.Reservation{}, nil)
	if err != nil {
		return nil, newError("failed to bind to port", err)
	}
	c := &conn{stack: d, writer: d.writer, reader: make(chan Payload, 10)}
	c.localAddr = &net.TCPAddr{IP: d.localIP, Port: int(p)}
	c.remoteAddr = addr

	d.router.Store(int(p), c)

	return c, nil
}

func (d *TCP) send() {
	for {
		select {
		case <-d.ctx.Done():
			return
		case buf := <-d.writer:
			d.driver.Write(buf)
		}
	}
}

func (d *TCP) recv() {
	maxRetryDelay := time.Second * 30
	retryDelay := time.Millisecond
	buf := make([]byte, d.driver.iface.MTU)
	var ip4 layers.IPv4
	var tcp layers.TCP
	decoder := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &tcp)
	decoded := []gopacket.LayerType{}
	for {
		select {
		case <-d.ctx.Done():
			return
		default:
			_, err := d.driver.Read(buf)
			if err != nil {
				newError("tcp recv driver failed", err).AtError().WriteToLog()
				time.Sleep(retryDelay)
				retryDelay = retryDelay * 2
				if retryDelay > maxRetryDelay {
					retryDelay = maxRetryDelay
				}
				continue
			} else {
				retryDelay = time.Millisecond
			}
			err = decoder.DecodeLayers(buf, &decoded)
			if err != nil {
				newError("received invalid packet", err).AtDebug().WriteToLog()
				continue
			}
			if !ip4.DstIP.Equal(d.localIP) {
				newError("received packet for unknown ip", ip4.DstIP.String()).AtDebug().WriteToLog()
				continue
			}
			c, ok := d.router.Load(int(tcp.DstPort))
			if !ok {
				newError("received packet for unexpected port", tcp.DstPort).AtDebug().WriteToLog()
				continue
			}
			c.reader <- tcp.Payload
		}
	}
}

type conn struct {
	localAddr  *net.TCPAddr
	remoteAddr *net.TCPAddr
	stack      *TCP
	writer     chan<- []byte
	reader     chan Payload
}

// Close implements net.Conn.
func (c *conn) Close() error {
	if c.stack != nil {
		c.stack.router.Delete(c.localAddr.Port)
		c.stack.pm.ReleasePort(ports.Reservation{Port: uint16(c.localAddr.Port)})
		c.stack = nil
		return nil
	}
	return newError("already closed")
}

// LocalAddr implements net.Conn.
func (c *conn) LocalAddr() net.Addr {
	return c.localAddr
}

// Read implements net.Conn.
func (c *conn) Read(b []byte) (n int, err error) {
	panic("unimplemented")
}

// RemoteAddr implements net.Conn.
func (c *conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// SetDeadline implements net.Conn.
func (c *conn) SetDeadline(t time.Time) error {
	panic("unimplemented")
}

// SetReadDeadline implements net.Conn.
func (c *conn) SetReadDeadline(t time.Time) error {
	panic("unimplemented")
}

// SetWriteDeadline implements net.Conn.
func (c *conn) SetWriteDeadline(t time.Time) error {
	panic("unimplemented")
}

// Write implements net.Conn.
func (c *conn) Write(b []byte) (n int, err error) {
	panic("unimplemented")
}

var _ net.Conn = (*conn)(nil)

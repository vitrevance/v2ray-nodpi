package network

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/smallnest/ringbuffer"
	"github.com/v2fly/v2ray-core/v5/common/signal"
	"github.com/vitrevance/v2ray-nodpi/pkg/syncmap"
	"gvisor.dev/gvisor/pkg/tcpip/ports"
)

type TCP struct {
	driver                  *Driver
	pm                      *ports.PortManager
	rnd                     *rand.Rand
	localIP                 net.IP
	router                  syncmap.SyncMap[uint32, chan []byte]
	ctx                     context.Context
	cancel                  func()
	serializationBufferPool sync.Pool
}

func NewTCP(driver *Driver) (*TCP, error) {
	stack := &TCP{
		driver: driver,
		pm:     ports.NewPortManager(),
		rnd:    rand.New(rand.NewSource(time.Now().Unix())),
		serializationBufferPool: sync.Pool{New: func() any {
			return gopacket.NewSerializeBuffer()
		}},
		localIP: driver.ip,
	}

	stack.pm.SetPortRange(50000, 60000)

	stack.ctx, stack.cancel = context.WithCancel(context.Background())

	go stack.recv()

	return stack, nil
}

func (d *TCP) Close() error {
	d.cancel()
	return d.driver.Close()
}

func (d *TCP) Dial(ctx context.Context, addr *net.TCPAddr) (*conn, error) {
	p, terr := d.pm.ReservePort(d.rnd, ports.Reservation{}, nil)
	if terr != nil {
		return nil, newError("failed to bind to port: ", terr)
	}
	c := &conn{
		stack:       d,
		readBuffer:  ringbuffer.New(8192).SetBlocking(true),
		writeBuffer: ringbuffer.New(8192).SetBlocking(true),
		windowSize:  8192,
		seq:         d.rnd.Uint32(),
		localAddr:   &net.TCPAddr{IP: d.localIP, Port: int(p)},
		remoteAddr:  addr,
	}

	driverChan := make(chan []byte, 10)

	d.router.Store(concatInt(uint16(c.localAddr.Port), uint16(c.remoteAddr.Port)), driverChan)

	// handshake
	err := c.handshake(driverChan, ctx)
	if err != nil {
		c.Close()
		return nil, newError("handshake failed").Base(err)
	}

	go c.background(d.ctx, driverChan)

	return c, nil
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
			if err != nil && d.ctx.Err() == nil {
				newError("tcp recv driver failed").Base(err).AtError().WriteToLog()
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
			if len(decoded) != 2 {
				newError("received invalid packet").Base(err).AtDebug().WriteToLog()
				continue
			}
			if !ip4.DstIP.Equal(d.localIP) {
				newError("received packet for unknown ip: ", ip4.DstIP.String()).AtDebug().WriteToLog()
				continue
			}
			if (ip4.Flags & layers.IPv4MoreFragments) != 0 {
				panic("not implemented: fragmented ip")
			}
			ch, ok := d.router.Load(concatInt(uint16(tcp.DstPort), uint16(tcp.SrcPort)))
			if !ok {
				newError("received packet for unexpected port: ", tcp.DstPort).AtDebug().WriteToLog()
				continue
			}
			ch <- slices.Clone(ip4.LayerPayload())
		}
	}
}

func (d *TCP) acquireBuffer() gopacket.SerializeBuffer {
	return d.serializationBufferPool.Get().(gopacket.SerializeBuffer)
}

func (d *TCP) releaseBuffer(serialBuffer gopacket.SerializeBuffer) {
	d.serializationBufferPool.Put(serialBuffer)
}

type conn struct {
	stack      *TCP
	localAddr  *net.TCPAddr
	remoteAddr *net.TCPAddr
	windowSize uint16

	readBuffer  *ringbuffer.RingBuffer
	writeBuffer *ringbuffer.RingBuffer

	wg     sync.WaitGroup
	closer sync.Once

	mux sync.Mutex
	seq uint32
	ack uint32
	fin bool
}

// Close implements net.Conn.
func (c *conn) Close() error {
	c.closer.Do(func() {
		c.readBuffer.CloseWithError(errors.New("closed"))
		c.writeBuffer.CloseWriter()
		c.wg.Wait()
		c.stack.router.Delete(concatInt(uint16(c.localAddr.Port), uint16(c.remoteAddr.Port)))
		c.stack.pm.ReleasePort(ports.Reservation{Port: uint16(c.localAddr.Port)})
	})
	return nil
}

// LocalAddr implements net.Conn.
func (c *conn) LocalAddr() net.Addr {
	return c.localAddr
}

// Read implements net.Conn.
func (c *conn) Read(b []byte) (n int, err error) {
	return c.readBuffer.Read(b)
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
	return c.writeBuffer.Write(b)
}

func (c *conn) background(ctx context.Context, driverInput <-chan []byte) {
	defer c.Close()

	timeoutDuration := time.Second * 30
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, timeoutDuration)
	defer cancel()

	c.wg.Add(2)
	defer c.wg.Wait()

	// read incoming messages
	go func() {
		defer c.wg.Done()
		defer cancel()
		var tcpIn layers.TCP
		decoder := gopacket.NewDecodingLayerParser(layers.LayerTypeTCP, &tcpIn)
		decoded := []gopacket.LayerType{}
		for {
			buf, err := readOrTimeout(driverInput, ctx)
			if err != nil {
				return
			}
			timer.Update()
			decoder.DecodeLayers(buf, &decoded)
			if len(decoded) != 1 {
				panic("must be already parsed")
			}
			err = c.handleIncoming(&tcpIn)
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer c.wg.Done()
		defer func() {
			c.mux.Lock()
			defer c.mux.Unlock()
			seq := c.seq
			ack := c.ack
			c.sendFin(seq, ack)
			c.seq++
		}()

		sendBuffer := make([]byte, c.windowSize)

		for {
			n, err := c.writeBuffer.Read(sendBuffer)
			if err != nil && n == 0 {
				return
			}
			c.mux.Lock()
			seq := c.seq
			ack := c.ack
			c.seq += uint32(n)
			c.mux.Unlock()
			c.sendData(seq, ack, sendBuffer[:n])
		}
	}()
}

func (c *conn) handleIncoming(tcpIn *layers.TCP) error {
	c.mux.Lock()
	defer c.mux.Unlock()
	if tcpIn.Seq != c.ack {
		newError("skipping packet").AtDebug().WriteToLog()
		return nil
	}
	nWritten, _ := c.readBuffer.Write(tcpIn.Payload)
	if tcpIn.RST {
		err := errors.New("connection reset")
		c.writeBuffer.CloseWithError(err)
		return err
	}
	if tcpIn.FIN && !c.fin {
		c.fin = true
		nWritten++
		c.readBuffer.CloseWriter()
	}
	c.ack += uint32(nWritten)
	if nWritten > 0 || tcpIn.FIN {
		return c.sendAck(c.seq, c.ack)
	}
	if !tcpIn.FIN && tcpIn.ACK && c.fin {
		return newError("finished")
	}
	return nil
}

func (c *conn) handshake(driverInput <-chan []byte, ctx context.Context) error {
	var ip4 layers.IPv4
	var tcpIn layers.TCP
	var tcpOut layers.TCP
	tcpOut.SetNetworkLayerForChecksum(&ip4)
	decoder := gopacket.NewDecodingLayerParser(layers.LayerTypeTCP, &tcpIn)
	decoded := []gopacket.LayerType{}
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	serialBuffer := c.stack.acquireBuffer()
	defer c.stack.releaseBuffer(serialBuffer)
	// SYN
	ip4 = layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    c.localAddr.IP,
		DstIP:    c.remoteAddr.IP,
		Protocol: layers.IPProtocolTCP,
	}
	tcpOut.SYN = true
	tcpOut.Seq = c.seq
	tcpOut.Window = c.windowSize
	tcpOut.SrcPort = layers.TCPPort(c.localAddr.Port)
	tcpOut.DstPort = layers.TCPPort(c.remoteAddr.Port)
	err := gopacket.SerializeLayers(serialBuffer, opts, &ip4, &tcpOut)
	if err != nil {
		return newError("tcp handshake failed").Base(err)
	}
	_, err = c.stack.driver.Write(serialBuffer.Bytes())
	if err != nil {
		return newError("tcp handshake failed").Base(err)
	}
	// SYN+ACK
	buf, err := readOrTimeout(driverInput, ctx)
	if err != nil {
		return newError("connection timeout").Base(err)
	}
	err = decoder.DecodeLayers(buf, &decoded)
	if err != nil {
		panic("must be already parsed")
	}
	if !tcpIn.ACK || !tcpIn.SYN || tcpIn.RST {
		return newError("tcp handshake failed due to server response")
	}
	if c.seq+1 != tcpIn.Ack {
		return newError("tcp handshake failed due to invalid server ACK")
	}
	c.ack = tcpIn.Seq + 1
	c.seq = tcpIn.Ack

	// ACK
	tcpOut = layers.TCP{}
	tcpOut.SetNetworkLayerForChecksum(&ip4)
	tcpOut.ACK = true
	tcpOut.Ack = c.ack
	tcpOut.Seq = c.seq
	tcpOut.Window = c.windowSize
	tcpOut.SrcPort = layers.TCPPort(c.localAddr.Port)
	tcpOut.DstPort = layers.TCPPort(c.remoteAddr.Port)
	err = gopacket.SerializeLayers(serialBuffer, opts, &ip4, &tcpOut)
	if err != nil {
		return newError("tcp handshake failed").Base(err)
	}
	_, err = c.stack.driver.Write(serialBuffer.Bytes())
	if err != nil {
		return newError("tcp handshake failed").Base(err)
	}
	return nil
}

func (c *conn) sendAck(seq, ack uint32) error {
	tcpOut := layers.TCP{
		SrcPort: layers.TCPPort(c.localAddr.Port),
		DstPort: layers.TCPPort(c.remoteAddr.Port),
		Seq:     seq,
		Ack:     ack,
		ACK:     true,
		Window:  uint16(c.readBuffer.Free()),
	}
	return c.sendTCP(&tcpOut, nil)
}

func (c *conn) sendData(seq, ack uint32, data []byte) error {
	tcpOut := layers.TCP{
		SrcPort: layers.TCPPort(c.localAddr.Port),
		DstPort: layers.TCPPort(c.remoteAddr.Port),
		Seq:     seq,
		Ack:     ack,
		ACK:     true,
		PSH:     true,
		Window:  uint16(c.readBuffer.Free()),
	}
	return c.sendTCP(&tcpOut, data)
}

func (c *conn) sendFin(seq, ack uint32) error {
	tcpOut := layers.TCP{
		SrcPort: layers.TCPPort(c.localAddr.Port),
		DstPort: layers.TCPPort(c.remoteAddr.Port),
		Seq:     seq,
		Ack:     ack,
		FIN:     true,
		PSH:     false,
		ACK:     true,
		Window:  uint16(c.readBuffer.Free()),
	}
	return c.sendTCP(&tcpOut, nil)
}

func (c *conn) Send(opts gopacket.SerializeOptions, ls ...gopacket.SerializableLayer) error {
	if len(ls) < 2 || ls[0].LayerType() != layers.LayerTypeIPv4 || ls[1].LayerType() != layers.LayerTypeTCP {
		return newError("unsupported layers")
	}
	serialBuffer := c.stack.acquireBuffer()
	defer c.stack.releaseBuffer(serialBuffer)
	err := gopacket.SerializeLayers(serialBuffer, opts, ls...)
	if err != nil {
		panic(err)
	}
	_, err = c.stack.driver.Write(serialBuffer.Bytes())
	if err != nil {
		return newError("send failed due to driver error").Base(err).AtError()
	}
	return nil
}

func (c *conn) sendTCP(tcpOut *layers.TCP, payload []byte) error {
	ip4 := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    c.localAddr.IP,
		DstIP:    c.remoteAddr.IP,
		Protocol: layers.IPProtocolTCP,
	}
	tcpOut.SetNetworkLayerForChecksum(&ip4)
	return c.Send(gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &ip4, tcpOut, gopacket.Payload(payload))
}

func readOrTimeout[T any](ch <-chan T, ctx context.Context) (T, error) {
	select {
	case value, ok := <-ch:
		if !ok {
			return value, newError("closed")
		}
		return value, nil
	case <-ctx.Done():
		var nl T
		return nl, ctx.Err()
	}
}

func concatInt(a, b uint16) uint32 {
	return (uint32(a) << 16) | uint32(b)
}

var _ net.Conn = (*conn)(nil)

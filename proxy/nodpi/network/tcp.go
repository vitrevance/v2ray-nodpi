package network

import (
	"context"
	"encoding/binary"
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
	"github.com/vitrevance/v2ray-nodpi/pkg/gensync"
	"gvisor.dev/gvisor/pkg/tcpip/ports"
)

type TCP struct {
	driver                  *Driver
	pm                      *ports.PortManager
	rnd                     *rand.Rand
	localIP                 net.IP
	router                  gensync.Map[uint32, chan []byte]
	ctx                     context.Context
	cancel                  func()
	serializationBufferPool gensync.Pool[gopacket.SerializeBuffer]
	segmentBufferPool       gensync.Pool[[]byte]
	defaultWindow           uint16
	segmentLimit            int
}

func NewTCP(driver *Driver) (*TCP, error) {
	const windowSize = 65535
	const segmentSize = 2048
	stack := &TCP{
		driver: driver,
		pm:     ports.NewPortManager(),
		rnd:    rand.New(rand.NewSource(time.Now().Unix())),
		serializationBufferPool: gensync.Pool[gopacket.SerializeBuffer]{New: func() any {
			return gopacket.NewSerializeBuffer()
		}},
		segmentBufferPool: gensync.Pool[[]byte]{
			New: func() any {
				return make([]byte, segmentSize)
			},
		},
		localIP:       driver.ip,
		defaultWindow: windowSize,
		segmentLimit:  segmentSize,
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

func (d *TCP) Dial(ctx context.Context, addr *net.TCPAddr) (*RawConn, error) {
	if addr == nil {
		return nil, newError("address is nil")
	}
	p, terr := d.pm.ReservePort(d.rnd, ports.Reservation{}, nil)
	if terr != nil {
		return nil, newError("failed to bind to port: ", terr)
	}
	c := &RawConn{
		stack:       d,
		readBuffer:  ringbuffer.New(int(d.defaultWindow)).SetBlocking(true),
		writeBuffer: ringbuffer.New(int(d.defaultWindow)).SetBlocking(true),
		windowSize:  d.defaultWindow,
		seq:         d.rnd.Uint32(),
		localAddr:   &net.TCPAddr{IP: d.localIP, Port: int(p)},
		remoteAddr:  addr,
	}

	driverChan := make(chan []byte, 10)

	d.router.Store(concatInt(uint16(c.localAddr.Port), uint16(c.remoteAddr.Port)), driverChan)

	// handshake
	err := c.handshake(driverChan, ctx)
	if err != nil {
		c.sendRst(c.seq, c.ack)
		c.Close()
		return nil, newError("handshake failed").Base(err)
	}

	go c.background(d.ctx, driverChan)

	return c, nil
}

func (d *TCP) recv() {
	const maxRetries = 10
	driverRetries := 0
	maxRetryDelay := time.Second * 2
	retryDelay := time.Millisecond
	etherBuf := make([]byte, 8192*2)
	var ip4 layers.IPv4
	var tcp layers.TCP
	decoder := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &tcp)
	decoded := []gopacket.LayerType{}

	for {
		select {
		case <-d.ctx.Done():
			return
		default:
			rdSize, err := d.driver.Read(etherBuf)
			if err != nil && d.ctx.Err() == nil {
				driverRetries++
				newError("tcp recv driver failed").Base(err).AtError().WriteToLog()
				time.Sleep(retryDelay)
				retryDelay = retryDelay * 2
				if retryDelay > maxRetryDelay {
					retryDelay = maxRetryDelay
				}
				if driverRetries > maxRetries {
					panic("driver did too many retries")
				}
				continue
			} else {
				driverRetries = 0
				retryDelay = time.Millisecond
			}
			buf := etherBuf[:rdSize]
			err = decoder.DecodeLayers(buf, &decoded)
			if len(decoded) == 0 {
				newError("received invalid packet").Base(err).AtDebug().WriteToLog()
				continue
			}
			if !ip4.DstIP.Equal(d.localIP) {
				newError("received packet for unknown ip: ", ip4.DstIP.String()).AtDebug().WriteToLog()
				continue
			}
			if len(decoded) != 2 {
				newError("received invalid packet").Base(err).AtWarning().WriteToLog()
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
			segmentBuf := d.acquireSegmentBuffer(len(ip4.LayerPayload()))
			n := copy(segmentBuf, ip4.LayerPayload())
			ch <- segmentBuf[:n]
		}
	}
}

func (d *TCP) acquireSerialBuffer() gopacket.SerializeBuffer {
	return d.serializationBufferPool.Get()
}

func (d *TCP) releaseSerialBuffer(serialBuffer gopacket.SerializeBuffer) {
	d.serializationBufferPool.Put(serialBuffer)
}

func (d *TCP) acquireSegmentBuffer(size int) []byte {
	if size > d.segmentLimit {
		return make([]byte, size)
	}
	return d.segmentBufferPool.Get()
}

func (d *TCP) releaseSegmentBuffer(serialBuffer []byte) {
	if cap(serialBuffer) == d.segmentLimit {
		d.segmentBufferPool.Put(serialBuffer[:cap(serialBuffer)])
	}
}

type RawConn struct {
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
	mss uint16
	fin bool

	inAck uint32
}

// Close implements net.Conn.
func (c *RawConn) Close() error {
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
func (c *RawConn) LocalAddr() net.Addr {
	return c.localAddr
}

// Read implements net.Conn.
func (c *RawConn) Read(b []byte) (n int, err error) {
	n, err = c.readBuffer.Read(b)
	return
}

// RemoteAddr implements net.Conn.
func (c *RawConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// SetDeadline implements net.Conn.
func (c *RawConn) SetDeadline(t time.Time) error {
	panic("unimplemented")
}

// SetReadDeadline implements net.Conn.
func (c *RawConn) SetReadDeadline(t time.Time) error {
	panic("unimplemented")
}

// SetWriteDeadline implements net.Conn.
func (c *RawConn) SetWriteDeadline(t time.Time) error {
	panic("unimplemented")
}

// Write implements net.Conn.
func (c *RawConn) Write(b []byte) (n int, err error) {
	n, err = c.writeBuffer.Write(b)
	return
}

var errOutOfOrder error = errors.New("out of order")
var errConnectionClosed error = errors.New("closed")
var errFinished error = errors.New("finished")

func (c *RawConn) background(ctx context.Context, driverInput <-chan []byte) {
	defer c.Close()

	timeoutDuration := time.Second * 15
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
		type orderedBuffer struct {
			seq uint32
			buf []byte
		}
		waitlist := make([]orderedBuffer, 0)

		handleIncoming := func(tcpIn *layers.TCP) error {
			c.mux.Lock()
			defer c.mux.Unlock()
			if tcpIn.Seq > c.ack {
				// newError("skipping packet, SEQ: ", tcpIn.Seq-c.inAck, " ACK: ", c.ack-c.inAck).AtDebug().WriteToLog()
				// debounceAck(c.seq, c.ack)
				c.sendAck(c.seq, c.ack)
				return errOutOfOrder
			}
			if tcpIn.Seq < c.ack && uint32(len(tcpIn.Payload))+tcpIn.Seq > c.ack {
				tcpIn.Payload = tcpIn.Payload[c.ack-tcpIn.Seq:]
				tcpIn.Seq = c.ack
			}
			if tcpIn.Seq != c.ack {
				return nil
			}
			nWritten, _ := c.readBuffer.Write(tcpIn.Payload)
			timer.Update()
			if tcpIn.RST {
				err := errConnectionClosed
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
				c.sendAck(c.seq, c.ack)
			}
			if !tcpIn.FIN && tcpIn.ACK && c.fin {
				return errFinished
			}
			return nil
		}

		defer c.readBuffer.CloseWriter()
		for {
			buf, err := readOrTimeout(driverInput, ctx)
			if err != nil {
				return
			}
			decoder.DecodeLayers(buf, &decoded)
			if len(decoded) != 1 {
				panic("must be already parsed")
			}
			waitlist = append(waitlist, orderedBuffer{
				seq: tcpIn.Seq,
				buf: buf,
			})
			slices.SortFunc(waitlist, func(a, b orderedBuffer) int {
				if a.seq == b.seq {
					return 0
				}
				if a.seq > b.seq {
					return -1
				}
				return 1
			})
			for err == nil && len(waitlist) > 0 {
				i := len(waitlist) - 1
				decoder.DecodeLayers(waitlist[i].buf, &decoded)
				err = handleIncoming(&tcpIn)
				if err == nil {
					c.stack.releaseSegmentBuffer(waitlist[i].buf)
					waitlist = waitlist[:i]
				}
			}
			// newError("holding back ", len(waitlist), " packets").AtDebug().WriteToLog()
			if err != nil && err != errOutOfOrder {
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

		bufferSize := uint16(c.stack.driver.iface.MTU) - 64
		if c.mss > 0 {
			bufferSize = min(c.mss, bufferSize)
		}
		sendBuffer := make([]byte, bufferSize)

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
			err = c.sendData(seq, ack, sendBuffer[:n])
			if err != nil {
				newError("failed to send segment").Base(err).AtError().WriteToLog()
			}
			timer.Update()
		}
	}()
}

func (c *RawConn) handshake(driverInput <-chan []byte, ctx context.Context) error {
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
	serialBuffer := c.stack.acquireSerialBuffer()
	defer c.stack.releaseSerialBuffer(serialBuffer)
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
	var maxMSS uint16 = uint16(c.stack.driver.iface.MTU) - 64
	tcpOut.Options = []layers.TCPOption{
		{
			OptionType:   layers.TCPOptionKindMSS,
			OptionLength: 2,
			OptionData:   []byte{byte(maxMSS >> 8), byte(maxMSS)},
		},
	}
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
	c.inAck = c.ack
	for _, opt := range tcpIn.Options {
		if opt.OptionType == layers.TCPOptionKindMSS {
			c.mss = binary.BigEndian.Uint16(opt.OptionData)
		}
	}

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

func (c *RawConn) sendAck(seq, ack uint32) error {
	return c.sendFilled(seq, ack, false, false, false, nil)
}

func (c *RawConn) sendFin(seq, ack uint32) error {
	return c.sendFilled(seq, ack, false, true, false, nil)
}

func (c *RawConn) sendData(seq, ack uint32, data []byte) error {
	return c.sendFilled(seq, ack, true, false, false, data)
}

func (c *RawConn) sendRst(seq, ack uint32) error {
	return c.sendFilled(seq, ack, true, false, true, nil)
}

func (c *RawConn) sendFilled(seq, ack uint32, push, fin, rst bool, data []byte) error {
	tcpOut := layers.TCP{
		SrcPort: layers.TCPPort(c.localAddr.Port),
		DstPort: layers.TCPPort(c.remoteAddr.Port),
		Seq:     seq,
		Ack:     ack,
		ACK:     true,
		PSH:     push,
		FIN:     fin,
		RST:     rst,
		Window:  uint16(c.readBuffer.Free()),
	}
	return c.sendTCP(&tcpOut, data)
}

func (c *RawConn) Send(opts gopacket.SerializeOptions, ls ...gopacket.SerializableLayer) error {
	if len(ls) < 2 || ls[0].LayerType() != layers.LayerTypeIPv4 || ls[1].LayerType() != layers.LayerTypeTCP {
		return newError("unsupported layers")
	}
	serialBuffer := c.stack.acquireSerialBuffer()
	defer c.stack.releaseSerialBuffer(serialBuffer)
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

func (c *RawConn) sendTCP(tcpOut *layers.TCP, payload []byte) error {
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

func (c *RawConn) SendWithOpts(payload []byte, opts ...func(*layers.IPv4, *layers.TCP) error) error {
	c.mux.Lock()
	defer c.mux.Unlock()
	ip4 := layers.IPv4{
		Version:  4,
		TTL:      32,
		SrcIP:    c.localAddr.IP,
		DstIP:    c.remoteAddr.IP,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(c.localAddr.Port),
		DstPort: layers.TCPPort(c.remoteAddr.Port),
		Seq:     c.seq,
		Ack:     c.ack,
		ACK:     true,
		PSH:     true,
		FIN:     false,
		Window:  uint16(c.readBuffer.Free()),
	}
	tcp.SetNetworkLayerForChecksum(&ip4)
	for _, opt := range opts {
		err := opt(&ip4, &tcp)
		if err != nil {
			return err
		}
	}
	return c.Send(gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &ip4, &tcp, gopacket.Payload(payload))
}

func readOrTimeout[T any](ch <-chan T, ctx context.Context) (T, error) {
	select {
	case value, ok := <-ch:
		if !ok {
			return value, errConnectionClosed
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

var _ net.Conn = (*RawConn)(nil)

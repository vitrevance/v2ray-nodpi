package nodpi

import (
	"net"
	"slices"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ConnOptions struct {
	srcIP   net.IP
	dstIP   net.IP
	srcPort uint16
	dstPort uint16
}

type Connection struct {
	ConnOptions
	// ipConn   net.PacketConn
	tcpConn  net.Conn
	sequence uint32
	rawFD    int
}

func GetFreePort() (port int, err error) {
	var a *net.TCPAddr
	if a, err = net.ResolveTCPAddr("tcp", "localhost:0"); err == nil {
		var l *net.TCPListener
		if l, err = net.ListenTCP("tcp", a); err == nil {
			defer l.Close()
			return l.Addr().(*net.TCPAddr).Port, nil
		}
	}
	return
}

func WrapTCPConn(under net.Conn) (*Connection, error) {
	conn := &Connection{}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return nil, newError("Failed to set IP_HDRINCL").Base(err)
	}

	conn.rawFD = fd

	conn.srcIP = under.LocalAddr().(*net.TCPAddr).IP
	conn.srcPort = uint16(under.LocalAddr().(*net.TCPAddr).Port)
	conn.dstIP = under.RemoteAddr().(*net.TCPAddr).IP
	conn.dstPort = uint16(under.RemoteAddr().(*net.TCPAddr).Port)

	conn.tcpConn = under

	conn.sequence = 1

	// ipConn, err := net.DialIP("ip4:tcp", &net.IPAddr{
	// 	IP: conn.srcIP,
	// }, &net.IPAddr{
	// 	IP: conn.dstIP,
	// })

	return conn, nil
}

// func NewTCPConn(address *net.TCPAddr) (*Connection, error) {
// 	freePort, err := GetFreePort()
// 	if err != nil {
// 		return nil, err
// 	}
// 	ipConn, err := net.ListenIP("ipv4", &net.IPAddr{
// 		IP: net.IPv4(127, 0, 0, 100),
// 	})
// 	if err != nil {
// 		return nil, err
// 	}
// 	conn := &Connection{ipConn: ipConn}
// 	conn.srcIP = net.IPv4(0, 0, 0, 0)
// 	conn.srcPort = uint16(freePort)
// 	conn.dstIP = address.IP
// 	conn.dstPort = uint16(address.Port)

// 	tcpConn, err := net.DialTCP("tcp", &net.TCPAddr{
// 		IP:   conn.srcIP,
// 		Port: int(conn.srcPort),
// 	}, &net.TCPAddr{
// 		IP:   conn.dstIP,
// 		Port: int(conn.dstPort),
// 	})
// 	if err != nil {
// 		ipConn.Close()
// 		return nil, err
// 	}
// 	conn.tcpConn = tcpConn
// 	return conn, nil
// }

func (c *Connection) WritePacket(p []byte) error {
	// return c.ipConn.WriteTo(p, &net.IPAddr{
	// 	IP: c.dstIP,
	// })
	err := syscall.Sendto(c.rawFD, p, 0, &syscall.SockaddrInet4{
		Addr: [4]byte(c.dstIP),
	})
	return err
}

type PreparedPacket struct {
	ip      *layers.IPv4
	tcp     *layers.TCP
	payload gopacket.Payload
}

func (c *Connection) SerialziePacket(p *PreparedPacket, opts gopacket.SerializeOptions) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buf, opts, p.ip, p.tcp, p.payload)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (c *Connection) PreparePacket(payload []byte) *PreparedPacket {
	ip := &layers.IPv4{
		Version:  4,
		Protocol: layers.IPProtocolTCP,
		TTL:      128,
		DstIP:    c.dstIP,
		SrcIP:    c.srcIP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(c.srcPort),
		DstPort: layers.TCPPort(c.dstPort),
		Seq:     c.sequence,
		Ack:     0,
		ACK:     false,
		SYN:     false,
		FIN:     false,
		RST:     false,
		URG:     false,
		ECE:     false,
		CWR:     false,
		NS:      false,
		PSH:     false,
		Window:  14600,
	}
	c.sequence++
	tcp.SetNetworkLayerForChecksum(ip)
	return &PreparedPacket{
		ip:      ip,
		tcp:     tcp,
		payload: payload,
	}
}

func (c *Connection) Write(tcpPayload []byte) (int, error) {
	// p := c.PreparePacket(tcpPayload)
	// b, err := c.SerialziePacket(p, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true})
	// if err != nil {
	// 	return 0, err
	// }
	// return c.WritePacket(b)
	c.sequence++
	return c.tcpConn.Write(tcpPayload)
}

func (c *Connection) Read(buffer []byte) (int, error) {
	size, err := c.tcpConn.Read(buffer)
	return size, err
}

func (c *Connection) Close() error {
	// c.ipConn.Close()
	syscall.Close(c.rawFD)
	return c.tcpConn.Close()
}

func (c *Connection) LocalAddr() net.Addr {
	return c.tcpConn.LocalAddr()
}

func (c *Connection) RemoteAddr() net.Addr {
	return c.tcpConn.RemoteAddr()
}

func (c *Connection) SetDeadline(t time.Time) error {
	return c.tcpConn.SetDeadline(t)
}

func (c *Connection) SetReadDeadline(t time.Time) error {
	return c.tcpConn.SetReadDeadline(t)
}

func (c *Connection) SetWriteDeadline(t time.Time) error {
	return c.tcpConn.SetWriteDeadline(t)
}

func SendReverseOrder(conn *Connection, payloads ...[]byte) error {
	packs := make([]*PreparedPacket, 0)
	for _, load := range payloads {
		packs = append(packs, conn.PreparePacket(load))
	}
	slices.Reverse(packs)
	for _, p := range packs {
		b, err := conn.SerialziePacket(p, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true})
		if err != nil {
			return err
		}
		err = conn.WritePacket(b)
		if err != nil {
			return err
		}
	}
	return nil
}

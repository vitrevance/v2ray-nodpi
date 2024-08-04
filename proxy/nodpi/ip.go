package nodpi

import (
	"net"
	"slices"
	"time"

	vnet "github.com/v2fly/v2ray-core/v5/common/net"

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
	ipConn   net.PacketConn
	sequence uint32
}

func NewTCPConn(address vnet.Destination) (*Connection, error) {
	ipConn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	conn := &Connection{ipConn: ipConn}
	conn.srcIP = ipConn.LocalAddr().(*net.TCPAddr).IP
	conn.srcPort = uint16(ipConn.LocalAddr().(*net.TCPAddr).Port)
	conn.dstIP = address.Address.IP()
	conn.dstPort = uint16(address.Port)
	return conn, nil
}

func (c *Connection) WritePacket(p []byte) (int, error) {
	return c.ipConn.WriteTo(p, &net.IPAddr{
		IP: c.dstIP,
	})
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
		SYN:     true,
		FIN:     false,
		RST:     false,
		URG:     false,
		ECE:     false,
		CWR:     false,
		NS:      false,
		PSH:     false,
		Window:  14600,
	}
	tcp.SetNetworkLayerForChecksum(ip)
	return &PreparedPacket{
		ip:      ip,
		tcp:     tcp,
		payload: payload,
	}
}

func (c *Connection) Write(tcpPayload []byte) (int, error) {
	p := c.PreparePacket(tcpPayload)
	b, err := c.SerialziePacket(p, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true})
	if err != nil {
		return 0, err
	}
	return c.WritePacket(b)
}

func (c *Connection) Read(buffer []byte) (int, error) {
	size, _, err := c.ipConn.ReadFrom(buffer)
	return size, err
}

func (c *Connection) Close() error {
	return c.ipConn.Close()
}

func (c *Connection) LocalAddr() net.Addr {
	return c.ipConn.LocalAddr()
}

func (c *Connection) RemoteAddr() net.Addr {
	return c.RemoteAddr()
}

func (c *Connection) SetDeadline(t time.Time) error {
	return c.ipConn.SetDeadline(t)
}

func (c *Connection) SetReadDeadline(t time.Time) error {
	return c.ipConn.SetReadDeadline(t)
}

func (c *Connection) SetWriteDeadline(t time.Time) error {
	return c.ipConn.SetWriteDeadline(t)
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
		conn.WritePacket(b)
	}
	return nil
}

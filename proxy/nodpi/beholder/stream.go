package beholder

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/vitrevance/v2ray-nodpi/pkg/gensync"
)

type ConnState struct {
	Seq uint32
	Ack uint32
}

type Beholder struct {
	mapper  gensync.Map[uint32, ConnState]
	handle  *pcap.Handle
	source  *gopacket.PacketSource
	localIP net.IP
}

// Get preferred outbound ip of this machine
func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

func NewBeholder(iface string) (*Beholder, error) {
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	src := gopacket.NewPacketSource(handle, handle.LinkType())

	res := &Beholder{
		handle:  handle,
		source:  src,
		localIP: GetOutboundIP(),
	}

	go res.listen()

	return res, nil
}

func (b *Beholder) GetRecent(port uint32) (ConnState, bool) {
	return b.mapper.Load(port)
}

func (b *Beholder) listen() {
	for p := range b.source.Packets() {
		if p.TransportLayer() != nil && p.TransportLayer().LayerType() == layers.LayerTypeTCP {
			tcp := p.TransportLayer().(*layers.TCP)
			if tcp.ACK && net.IP(p.NetworkLayer().NetworkFlow().Src().Raw()).Equal(b.localIP) {
				b.mapper.Store(uint32(tcp.SrcPort), ConnState{
					Seq: tcp.Seq,
					Ack: tcp.Ack,
				})
			}
		}
	}
	b.handle.Close()
}

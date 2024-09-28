package network

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/packet"
	"github.com/stretchr/testify/require"
)

func TestDriver(t *testing.T) {
	d, err := NewDriver()
	require.NoError(t, err)

	d.Close()
}

func TestUDP(t *testing.T) {
	d, err := NewDriver()
	require.NoError(t, err)
	defer d.Close()

	ip := &layers.IPv4{
		SrcIP:    net.IP{172, 29, 5, 194},
		DstIP:    net.IP{192, 168, 0, 200},
		Version:  4,
		Protocol: layers.IPProtocolUDP,
		TTL:      45,
	}
	udp := &layers.UDP{
		SrcPort: 8080,
		DstPort: 5555,
	}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	gopacket.SerializeLayers(buf, opts, ip, udp, gopacket.Payload([]byte("hello")))
	require.NoError(t, err)

	dst := &packet.Addr{HardwareAddr: layers.EthernetBroadcast}

	_, err = d.conn.WriteTo(buf.Bytes(), dst)
	require.NoError(t, err)
}

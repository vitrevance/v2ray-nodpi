package network

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func SendWithOpts(driver *Driver, payload []byte, opts ...func(*layers.IPv4, *layers.TCP) error) error {
	ip4 := layers.IPv4{
		Version:  4,
		TTL:      32,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		ACK:    true,
		PSH:    true,
		FIN:    false,
		Window: 65535,
	}
	tcp.SetNetworkLayerForChecksum(&ip4)
	for _, opt := range opts {
		err := opt(&ip4, &tcp)
		if err != nil {
			return err
		}
	}
	serialBuffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(serialBuffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &ip4, &tcp, gopacket.Payload(payload))
	if err != nil {
		return err
	}
	_, err = driver.Write(serialBuffer.Bytes())
	return err
}

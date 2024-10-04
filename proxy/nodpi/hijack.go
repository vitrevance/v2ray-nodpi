package nodpi

import (
	"time"

	"github.com/google/gopacket/layers"
)

func sendFakeTLS(conn TCPConn, ttl uint8) error {
	err := conn.SendWithOpts([]byte("hehehe"), func(i *layers.IPv4, t *layers.TCP) error {
		i.TTL = ttl
		return nil
	})
	if err != nil {
		return err
	}
	time.Sleep(time.Millisecond * 100)
	return nil
}

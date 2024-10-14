package network

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/smallnest/ringbuffer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTCP(t *testing.T) {
	var httpGet = "GET / HTTP/1.1\r\nHost: 192.168.0.200\r\n\r\n"
	d, err := NewDriver()
	require.NoError(t, err)
	defer d.Close()

	tcp, err := NewTCP(d)
	require.NoError(t, err)
	defer tcp.Close()

	c, err := tcp.Dial(context.Background(), &net.TCPAddr{IP: net.IPv4(192, 168, 0, 200), Port: 50000})
	require.NoError(t, err)
	defer c.Close()

	_, err = c.Write([]byte(httpGet))
	require.NoError(t, err)

	buf := make([]byte, 1024)
	rd := 0
	for err == nil {
		n, rerr := c.Read(buf[rd:])
		rd += n
		err = rerr
	}
	require.Greater(t, rd, 0, err)

	resp := string(buf[:rd])

	t.Log(resp)

	assert.Contains(t, resp, "HTTP/1.1 307")
}

func TestBuffer(t *testing.T) {
	wg := sync.WaitGroup{}
	defer wg.Wait()

	b := ringbuffer.New(10).SetBlocking(true)

	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(time.Second)
		b.Write([]byte{1})
		b.CloseWriter()
	}()

	buf := make([]byte, 5)
	n, _ := b.Read(buf)
	require.Equal(t, 1, n)
}

func BenchmarkTCPDecoder(b *testing.B) {
	var httpGet = "GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"
	d, err := NewDriver()
	require.NoError(b, err)

	tcp, err := NewTCP(d)
	require.NoError(b, err)
	defer tcp.Close()

	wg := sync.WaitGroup{}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := tcp.Dial(ctx, &net.TCPAddr{IP: net.IPv4(64, 233, 164, 105), Port: 80})
			require.NoError(b, err)
			defer c.Close()

			_, err = c.Write([]byte(httpGet))
			assert.NoError(b, err)

			buf := make([]byte, 1024)
			rd := 0
			for err == nil {
				n, rerr := c.Read(buf)
				rd += n
				err = rerr
			}
			assert.Greater(b, rd, 0, err)
		}()
	}
	wg.Wait()
}

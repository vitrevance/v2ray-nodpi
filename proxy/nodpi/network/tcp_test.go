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

var httpGet = "GET / HTTP/1.1\nHost: 192.168.0.200\r\n\r\n"

func TestTCP(t *testing.T) {
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

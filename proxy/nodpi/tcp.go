package nodpi

import (
	"net"
	"syscall"
	"time"
)

type TCPConn struct {
	src *net.TCPAddr
	dst *net.TCPAddr
	fd  int
}

func DialTCP(remote *net.TCPAddr) (*TCPConn, error) {
	// lip, err := GetLocalIP()
	// if err != nil {
	// 	return nil, err
	// }
	// p, err := GetFreePort()
	// if err != nil {
	// 	return nil, err
	// }
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}
	// if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
	// 	syscall.Close(fd)
	// 	return nil, newError("Failed to set IP_HDRINCL").Base(err)
	// }
	// if err := syscall.Bind(fd, &syscall.SockaddrInet4{
	// 	Addr: [4]byte(lip),
	// 	Port: p,
	// }); err != nil {
	// 	syscall.Close(fd)
	// 	return nil, newError("Failed to bind TCP socket").Base(err)
	// }
	if err := syscall.Connect(fd, &syscall.SockaddrInet4{
		Addr: [4]byte(remote.IP),
		Port: remote.Port,
	}); err != nil {
		syscall.Close(fd)
		return nil, newError("Failed to connect TCP socket").Base(err)
	}

	sa, err := syscall.Getsockname(fd)
	if err != nil {
		syscall.Close(fd)
		return nil, newError("Failed to retrieve TCP socket port").Base(err)
	}
	sockaddr := sa.(*syscall.SockaddrInet4)

	conn := new(TCPConn)
	conn.src = &net.TCPAddr{
		IP:   sockaddr.Addr[:],
		Port: sockaddr.Port,
	}
	conn.dst = remote
	conn.fd = fd
	return conn, nil
}

func (c *TCPConn) DisableDelay(state bool) error {
	if state {
		return syscall.SetsockoptInt(c.fd, syscall.SOL_TCP, syscall.TCP_NODELAY, 1)
	} else {
		return syscall.SetsockoptInt(c.fd, syscall.SOL_TCP, syscall.TCP_NODELAY, 0)
	}
}

func (c *TCPConn) SetTTL(ttl int) error {
	return syscall.SetsockoptInt(c.fd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
}

func (c *TCPConn) Write(tcpPayload []byte) (int, error) {
	return syscall.Write(c.fd, tcpPayload)
}

func (c *TCPConn) Read(buffer []byte) (int, error) {
	return syscall.Read(c.fd, buffer)
}

func (c *TCPConn) LocalAddr() net.Addr {
	return c.src
}

func (c *TCPConn) RemoteAddr() net.Addr {
	return c.dst
}

func (c *TCPConn) SetDeadline(t time.Time) error {
	return newError("not implemented")
}

func (c *TCPConn) SetReadDeadline(t time.Time) error {
	return newError("not implemented")
}

func (c *TCPConn) SetWriteDeadline(t time.Time) error {
	return newError("not implemented")
}

func (c *TCPConn) Close() error {
	return syscall.Close(c.fd)
}

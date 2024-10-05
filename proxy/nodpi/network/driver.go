package network

import (
	"encoding/binary"
	"io"
	"net"
	"os/exec"
	"slices"

	"github.com/google/gopacket/layers"
	"github.com/mdlayher/packet"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type Driver struct {
	iface *net.Interface
	conn  *packet.Conn
	ip    net.IP
}

func NewDriver() (*Driver, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, newError("failed to get interfaces").Base(err)
	}
	if len(ifaces) == 0 {
		return nil, newError("no available network interfaces")
	}
	errors := make([]error, 0)
	for _, iface := range ifaces {
		if len(iface.HardwareAddr) == 6 && iface.Flags&(net.FlagUp|net.FlagMulticast|net.FlagBroadcast) != 0 {
			lnk, err := netlink.LinkByName(iface.Name)
			if err != nil {
				errors = append(errors, err)
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				errors = append(errors, err)
				continue
			}
			validIPs := make([]*net.IPNet, 0)
			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					if v.IP.To4() != nil {
						validIPs = append(validIPs, v)
					}
				case *net.IPAddr:
					if v.IP.To4() != nil {
						validIPs = append(validIPs, &net.IPNet{
							IP:   v.IP,
							Mask: v.IP.DefaultMask(),
						})
					}
				}
			}
			slices.SortFunc(validIPs, func(a, b *net.IPNet) int {
				ai := binary.BigEndian.Uint32(a.IP.To4())
				bi := binary.BigEndian.Uint32(b.IP.To4())
				if ai > bi {
					return 1
				} else if ai < bi {
					return -1
				}
				return 0
			})
			if len(validIPs) == 0 {
				errors = append(errors, newError("no vlaid ip to bind to"))
				continue
			}
			chosenIP := validIPs[0].IP.To4()
			if len(validIPs) == 1 {
				if validIPs[0].IP.To4()[3] == 0 {
					errors = append(errors, newError("interface has single zero-ending IP"))
					continue
				}
				validIPs[0].Mask = []byte{0xff, 0xff, 0xff, 0xff}
				validIPs[0].IP.To4()[3] = 0
				chosenIP = validIPs[0].IP.To4()
				err = netlink.AddrAdd(lnk, &netlink.Addr{
					IPNet: validIPs[0],
				})
				if err != nil {
					errors = append(errors, newError("failed to add IP to interface").Base(err))
					continue
				}
			}
			cmd := exec.Command("iptables", "-C", "INPUT", "-d", chosenIP.String(), "-p", "tcp", "-j", "QUEUE")
			err = cmd.Run()
			if err != nil {
				cmd := exec.Command("iptables", "-A", "INPUT", "-d", chosenIP.String(), "-p", "tcp", "-j", "QUEUE")
				msg, err := cmd.CombinedOutput()
				if err != nil {
					return nil, newError("failed to configure ip filters: ", string(msg)).Base(err)
				}
			}
			conn, err := packet.Listen(&iface, packet.Datagram, unix.ETH_P_IP, nil)
			if err != nil {
				continue
			}
			return &Driver{
				iface: &iface,
				conn:  conn,
				ip:    chosenIP,
			}, nil
		}
	}
	return nil, newError("all interfaces failed", ifaces, errors)
}

func (d *Driver) Close() error {
	return d.conn.Close()
}

func (d *Driver) Write(b []byte) (int, error) {
	dst := &packet.Addr{HardwareAddr: layers.EthernetBroadcast}
	return d.conn.WriteTo(b, dst)
}

func (d *Driver) Read(buf []byte) (int, error) {
	n, mac, err := d.conn.ReadFrom(buf)
	_ = mac
	return n, err
}

var _ io.ReadWriteCloser = (*Driver)(nil)

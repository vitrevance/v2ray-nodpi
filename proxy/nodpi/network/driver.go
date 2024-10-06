package network

import (
	"encoding/binary"
	"io"
	"net"
	"os"
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
	iptablesTool := "iptables"
	if v, ok := os.LookupEnv("IPTABLES_TOOL"); ok {
		iptablesTool = v
		newError("using specified version of iptables: ", iptablesTool).AtWarning().WriteToLog()
	}
	var bindIP net.IP
	if v, ok := os.LookupEnv("BIND"); ok {
		bindIP = net.ParseIP(v).To4()
	}
	var bindIface string
	if v, ok := os.LookupEnv("IFACE"); ok {
		bindIface = v
	}
	var ifaces []net.Interface
	if bindIface == "" {
		var err error
		ifaces, err = net.Interfaces()
		if err != nil {
			return nil, newError("failed to get interfaces").Base(err)
		}
	} else {
		iface, err := net.InterfaceByName(bindIface)
		if err != nil {
			return nil, newError("failed to get interface ", bindIface).Base(err)
		}
		ifaces = append(ifaces, *iface)
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
			chosenIP := slices.Clone(validIPs[0].IP.To4())
			if bindIP != nil {
				chosenIP = bindIP
			} else {
				chosenIP[3] = 0
			}
			newError("candidate interface IP adress: ", iface.Name, chosenIP).AtWarning().WriteToLog()
			newError("candidate interface IP adresses: ", iface.Name, validIPs).AtWarning().WriteToLog()
			if !slices.ContainsFunc(validIPs, func(a *net.IPNet) bool {
				return chosenIP.Equal(a.IP.To4())
			}) {
				validIPs[0].Mask = []byte{0xff, 0xff, 0xff, 0xff}
				copy(validIPs[0].IP.To4(), chosenIP.To4())
				err = netlink.AddrAdd(lnk, &netlink.Addr{
					IPNet: validIPs[0],
				})
				if err != nil {
					errors = append(errors, newError("failed to add IP to interface").Base(err))
					continue
				}
			}
			cmd := exec.Command(iptablesTool, "-C", "INPUT", "-d", chosenIP.String(), "-p", "tcp", "-j", "DROP")
			err = cmd.Run()
			if err != nil {
				cmd := exec.Command(iptablesTool, "-A", "INPUT", "-d", chosenIP.String(), "-p", "tcp", "-j", "DROP")
				msg, err := cmd.CombinedOutput()
				if err != nil {
					return nil, newError("failed to configure ip filters: ", string(msg)).Base(err)
				}
			}
			conn, err := packet.Listen(&iface, packet.Datagram, unix.ETH_P_IP, nil)
			if err != nil {
				continue
			}
			if iface.MTU <= 0 {
				newError("interface MTU is set to 0 - resetting to default value: ", iface.Name).AtWarning().WriteToLog()
				iface.MTU = 1500
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

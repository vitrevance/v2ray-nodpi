package nodpi

import (
	"context"
	"fmt"
	"io"
	"time"

	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/common/dice"
	"github.com/v2fly/v2ray-core/v5/common/errors"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/retry"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"github.com/v2fly/v2ray-core/v5/common/signal"
	"github.com/v2fly/v2ray-core/v5/common/task"
	"github.com/v2fly/v2ray-core/v5/features/dns"
	"github.com/v2fly/v2ray-core/v5/features/policy"
	transport "github.com/v2fly/v2ray-core/v5/transport"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
)

// //go:generate go run github.com/v2fly/v2ray-core/v5/common/errors/errorgen
// //go:generate protoc --go_out=. --go_opt=paths=source_relative -I ../.. proxy/nodpi/config.proto
//go:generate protoc --go_out=../.. --go_opt=paths=source_relative -I ../.. proxy/nodpi/config.proto

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config any) (any, error) {
		h := new(Handler)
		if err := core.RequireFeatures(ctx, func(pm policy.Manager, d dns.Client) error {
			return h.Init(config.(*Config), pm, d)
		}); err != nil {
			return nil, err
		}
		return h, nil
	}))
}

type Handler struct {
	policyManager policy.Manager
	dns           dns.Client
	config        *Config
}

func (h *Handler) Init(config *Config, pm policy.Manager, d dns.Client) error {
	h.config = config
	h.policyManager = pm
	h.dns = d

	return nil
}

func (h *Handler) resolveIP(domain string) net.Address {
	ips, err := dns.LookupIPWithOption(h.dns, domain, dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: false,
		FakeEnable: false,
	})
	if err != nil {
		newError("failed to get IP address for domain ", domain).Base(err).WriteToLog()
	}
	if len(ips) == 0 {
		return nil
	}
	return net.IPAddress(ips[dice.Roll(len(ips))])
}

func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("target not specified.")
	}

	// outbound.Resolver = func(ctx context.Context, domain string) net.Address {
	// 	return h.resolveIP(ctx, domain)
	// }

	destination := outbound.Target
	newError("opening connection to ", destination).WriteToLog(session.ExportIDToError(ctx))

	input := link.Reader
	output := link.Writer

	var conn internet.Connection
	err := retry.ExponentialBackoff(5, 100).On(func() error {
		var rawConn internet.Connection
		var err error
		if destination.Network == net.Network_TCP {
			addr := h.resolveIP(outbound.Target.Address.String())
			// rawConn, err = NewTCPConn(&net.TCPAddr{
			// 	IP:   addr.IP(),
			// 	Port: int(destination.Port),
			// })
			var under internet.Connection
			// under, err = dialer.Dial(ctx, destination)
			under, err = DialTCP(&net.TCPAddr{IP: addr.IP(), Port: int(destination.Port)})
			if err != nil {
				return err
			}
			rawConn, err = WrapTCPConn(under)
			// rawConn, err = DialTCP(&net.TCPAddr{IP: addr.IP(), Port: int(destination.Port)})
		} else {
			rawConn, err = dialer.Dial(ctx, destination)
		}
		if err != nil {
			return err
		}
		conn = rawConn
		return nil
	})
	if err != nil {
		return newError("failed to open connection to ", destination).Base(err)
	}
	defer conn.Close()

	timeoutDuration := time.Second * 5
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, timeoutDuration)

	requestDone := func() error {
		defer timer.SetTimeout(timeoutDuration)

		var writer buf.Writer
		if destination.Network == net.Network_TCP {
			// writer = buf.NewWriter(conn)
			err := h.performRequest(input, conn.(*Connection), timer)
			if err != nil {
				return newError("failed to process TCP request").Base(err)
			}
		} else {
			writer = &buf.SequentialWriter{Writer: conn}
			if err := buf.Copy(input, writer, buf.UpdateActivity(timer)); err != nil {
				return newError("failed to process request").Base(err)
			}
		}

		return nil
	}

	responseDone := func() error {
		defer timer.SetTimeout(timeoutDuration)

		var reader buf.Reader
		if destination.Network == net.Network_TCP {
			reader = buf.NewReader(conn)
		} else {
			reader = buf.NewPacketReader(conn)
		}
		if err := buf.Copy(reader, output, buf.UpdateActivity(timer)); err != nil {
			return newError("failed to process response").Base(err)
		}

		return nil
	}

	if err := task.Run(ctx, requestDone, task.OnSuccess(responseDone, task.Close(output))); err != nil {
		fmt.Println(err.Error())
		return newError("connection ends").Base(err)
	}

	return nil
}

func (h *Handler) performRequest(input buf.Reader, conn *Connection, timer *signal.ActivityTimer) error {
	var err error = ReadMore
	var tls TLSRecord
	var raw []byte
	for err != nil && errors.Cause(err) == ReadMore {
		inBuffer, readErr := input.ReadMultiBuffer()
		if readErr != nil && (errors.Cause(readErr) != io.EOF || errors.Cause(err) == ReadMore) {
			return newError("failed to read TCP input").Base(err)
		}
		rawPart := buf.Compact(inBuffer)[0].Bytes()
		raw = append(raw, rawPart...)
		tls, err = parseTLSHandshake(raw)
	}
	if err != nil {
		newError("failed to parse TLS handshake").Base(err).WriteToLog()
		conn.Write(raw)
	} else {
		if tls.Body[0] != 1 {
			newError("this TLS is not a ClientHello - skipping").WriteToLog()
			conn.Write(raw)
		} else {
			totalTLSLength := len(tls.Body) + 5
			if totalTLSLength != len(raw) {
				newError("unexpected content in TLS packet").WriteToLog()
			}
			splitSize := int(h.config.GetChunkSize())
			if pos := containsSubslice(tls.Body, []byte("googlevideo")); pos != -1 {
				newError("this TLS is from youtube YAY!").WriteToLog()
				splitSize = pos + 3
				// h.sendFakeHTTPS(conn)
			}
			parts := make([][]byte, 0)
			for len(tls.Body) > splitSize {
				rest, err := tls.Split(splitSize)
				if err != nil {
					return newError("failed to split TLS").Base(err)
				}
				// newRaw = append(newRaw, tls.Encode()...)
				parts = append(parts, tls.Encode())
				tls = rest
				timer.Update()
			}
			if len(tls.Body) > 0 {
				// newRaw = append(newRaw, tls.Encode()...)
				parts = append(parts, tls.Encode())
			}
			// err = SendReverseOrder(conn, parts...)
			conn.SendFakeHTTPS()
			// err = conn.DisableDelay(true)
			// if err != nil {
			// 	return newError("failed to disable delay").Base(err)
			// }
			// err = conn.SetTTL(3)
			// if err != nil {
			// 	return newError("failed to decrease TTL").Base(err)
			// }
			// conn.Write(FakeHTTPSPayload)
			time.Sleep(time.Millisecond * 50)
			// err = conn.SetTTL(64)
			if err != nil {
				return newError("failed to restore TTL").Base(err)
			}
			for _, part := range parts {
				_, err = conn.Write(part)
				// time.Sleep(time.Millisecond * time.Duration(h.config.ChunkDelay))
			}
			if err != nil {
				return newError("failed to send tls reverse order").Base(err)
			}
			// err = conn.DisableDelay(false)
			if err != nil {
				return newError("failed to enable delay").Base(err)
			}
			if len(raw) > totalTLSLength {
				conn.Write(raw[totalTLSLength:])
			}
			// conn.Write(raw)
		}
	}

	if err := buf.Copy(input, buf.NewWriter(conn), buf.UpdateActivity(timer)); err != nil {
		return newError("failed to process request").Base(err)
	}
	return nil
}

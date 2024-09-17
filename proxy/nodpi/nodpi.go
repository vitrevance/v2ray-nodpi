package nodpi

import (
	"context"
	"fmt"
	"io"
	"regexp"
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

	outbound.Resolver = func(ctx context.Context, domain string) net.Address {
		return h.resolveIP(domain)
	}

	destination := outbound.Target
	newError("opening connection to ", destination).WriteToLog(session.ExportIDToError(ctx))

	input := link.Reader
	output := link.Writer

	var conn internet.Connection
	err := retry.ExponentialBackoff(5, 100).On(func() error {
		var rawConn internet.Connection
		var err error
		rawConn, err = dialer.Dial(ctx, destination)
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
			err := h.performRequest(input, conn, timer)
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

func (h *Handler) performRequest(input buf.Reader, conn net.Conn, timer *signal.ActivityTimer) error {
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
		newError("failed to parse TLS handshake").Base(err).AtInfo().WriteToLog()
		conn.Write(raw)
	} else {
		if tls.Body[0] != 1 {
			newError("this TLS is not a ClientHello - skipping").AtInfo().WriteToLog()
			conn.Write(raw)
		} else {
			if h.config.GetSniFilters() != nil {
				sni := tls.SNI()
				if !h.filterSNI(sni) {
					conn.Close()
					return newError("blocked request by SNI: ", sni).AtInfo()
				}
			}
			conn.Write(raw[:1])
			time.Sleep(time.Millisecond * time.Duration(h.config.ChunkDelay))
			raw = raw[1:]
			if h.config.ChunkSize > 0 {
				for uint32(len(raw)) > h.config.ChunkSize {
					conn.Write(raw[:h.config.ChunkSize])
					raw = raw[h.config.ChunkSize:]
				}
			}
			conn.Write(raw)
		}
	}

	if err := buf.Copy(input, buf.NewWriter(conn), buf.UpdateActivity(timer)); err != nil {
		return newError("failed to process request").Base(err)
	}
	return nil
}

func (h *Handler) filterSNI(sni string) bool {
	for _, v := range h.config.GetSniFilters().GetWhitelist() {
		re, err := regexp.Compile(v)
		if err != nil {
			newError("this TLS is not a ClientHello - skipping").AtWarning().WriteToLog()
			continue
		}
		if !re.MatchString(sni) {
			return false
		}
	}
	for _, v := range h.config.GetSniFilters().GetBlacklist() {
		re, err := regexp.Compile(v)
		if err != nil {
			newError("this TLS is not a ClientHello - skipping").AtWarning().WriteToLog()
			continue
		}
		if re.MatchString(sni) {
			return false
		}
	}
	return true
}

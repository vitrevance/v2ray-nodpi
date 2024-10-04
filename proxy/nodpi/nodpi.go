package nodpi

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/google/gopacket/layers"
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
	policyManager  policy.Manager
	dns            dns.Client
	config         *Config
	blockPredictor *BlockPredictor
	dialer         TCPDialer
}

func (h *Handler) Init(config *Config, pm policy.Manager, d dns.Client) error {
	h.config = config
	h.policyManager = pm
	h.dns = d

	if config.GetSniFilters().GetAdaptiveMode() {
		h.blockPredictor = NewBlockPredictor()
	}
	if config.GetIspTtl() > 0 {
		var err error
		h.dialer, err = NewTCPDialer()
		if err != nil {
			return newError("failed to use custom TCP satck").Base(err).AtError()
		}
	}

	return nil
}

func (h *Handler) resolveIP(domain string) net.Address {
	// if strings.Contains(domain, ".googlevideo.com") || strings.Contains(domain, "youtube.com") || strings.Contains(domain, ".gstatic.com") {
	// 	return net.IPAddress([]byte{74, 125, 99, 7})
	// }
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

func (h *Handler) Process(ctx context.Context, link *transport.Link, externalDialer internet.Dialer) error {
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

	scanResult, err := h.scanRequest(input)
	if err != nil {
		return newError("failed to scan request").Base(err).AtWarning()
	}

	dialer := WrapTCPDialer(externalDialer)
	if scanResult.ShouldIntercept && h.config.GetIspTtl() > 0 {
		dialer = h.dialer
	}

	var conn *ConnSentinel
	err = retry.ExponentialBackoff(5, 100).On(func() error {
		var rawConn TCPConn
		var err error
		rawConn, err = dialer.Dial(ctx, h.destinationToTCP(destination))
		if err != nil {
			return err
		}
		if h.config.GetSniFilters().GetAdaptiveMode() {
			conn = h.blockPredictor.NewReporter(rawConn)
		} else {
			conn = DummyReporter(rawConn)
		}
		return nil
	})
	if err != nil {
		return newError("failed to open connection to ", destination).Base(err)
	}
	defer conn.Close()

	conn.ReportSNI(scanResult.SNI)
	if scanResult.ShouldIntercept {
		conn.MarkCanceled()
	}

	timeoutDuration := time.Second * 30
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, timeoutDuration)

	requestDone := func() error {
		defer timer.SetTimeout(timeoutDuration)

		var writer buf.Writer
		if destination.Network == net.Network_TCP {
			// writer = buf.NewWriter(conn)
			err := h.performRequest(input, conn, &scanResult, timer)
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
			conn.ReportFailure()
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

type ScanResult struct {
	SNI             string
	ShouldIntercept bool
	raw             []byte
}

func (h *Handler) scanRequest(input buf.Reader) (ScanResult, error) {
	var err error = ReadMore
	var tls TLSRecord
	var raw []byte
	for err != nil && errors.Cause(err) == ReadMore {
		inBuffer, readErr := input.ReadMultiBuffer()
		if readErr != nil && (errors.Cause(readErr) != io.EOF || errors.Cause(err) == ReadMore) {
			return ScanResult{
				ShouldIntercept: false,
			}, newError("failed to read TCP input").Base(err)
		}
		rawPart := buf.Compact(inBuffer)[0].Bytes()
		raw = append(raw, rawPart...)
		tls, err = parseTLSHandshake(raw)
	}
	if err != nil {
		// newError("failed to parse TLS handshake").Base(err).AtInfo().WriteToLog()
		return ScanResult{
			ShouldIntercept: false,
			raw:             raw,
		}, nil
	} else {
		if tls.Body[0] != 1 {
			newError("this TLS is not a ClientHello - skipping").AtDebug().WriteToLog()
			return ScanResult{
				ShouldIntercept: false,
				raw:             raw,
			}, nil
		} else {
			var sni string
			if h.config.GetSniFilters() != nil || h.config.GetIspTtl() > 0 {
				sni = tls.SNI()
			}
			if h.config.GetSniFilters() != nil {
				if !h.filterSNI(sni) {
					return ScanResult{
						ShouldIntercept: false,
						SNI:             sni,
						raw:             raw,
					}, nil
				}
			}
			return ScanResult{
				ShouldIntercept: true,
				SNI:             sni,
				raw:             raw,
			}, nil
		}
	}
}

func (h *Handler) performRequest(input buf.Reader, conn *ConnSentinel, sr *ScanResult, timer *signal.ActivityTimer) error {
	var raw []byte = sr.raw
	if sr.ShouldIntercept {
		if h.config.GetIspTtl() == 0 {
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
		} else {
			ttl := uint8(h.config.GetIspTtl())
			buf := "hjksdfgkljsdfgklgafdljkbh"
			seq := uint32(0)
			conn.Conn.SendWithOpts([]byte(buf), func(i *layers.IPv4, t *layers.TCP) error {
				i.TTL = ttl
				seq = t.Seq
				return nil
			})
			for i := 0; i < 20; i++ {
				seq += uint32(len(buf))
				conn.Conn.SendWithOpts([]byte(buf), func(i *layers.IPv4, t *layers.TCP) error {
					i.TTL = ttl
					t.Seq = seq
					return nil
				})
			}
			conn.Write(raw)
		}
	} else {
		conn.Write(raw)
	}

	if err := buf.Copy(input, buf.NewWriter(conn), buf.UpdateActivity(timer)); err != nil {
		return newError("failed to process request").Base(err)
	}
	return nil
}

func (h *Handler) filterSNI(sni string) (allow bool) {
	allow = len(h.config.GetSniFilters().GetWhitelist()) == 0 && !h.config.GetSniFilters().GetAdaptiveMode()
	for _, v := range h.config.GetSniFilters().GetWhitelist() {
		re, err := regexp.Compile(v)
		if err != nil {
			newError("invalid regex: ", v).AtWarning().WriteToLog()
			continue
		}
		if re.MatchString(sni) {
			allow = true
		}
	}
	if !allow && h.config.GetSniFilters().GetAdaptiveMode() {
		allow = h.blockPredictor.PredictAllow(sni)
	}
	for _, v := range h.config.GetSniFilters().GetBlacklist() {
		re, err := regexp.Compile(v)
		if err != nil {
			newError("invalid regex: ", v).AtWarning().WriteToLog()
			continue
		}
		if re.MatchString(sni) {
			allow = false
		}
	}
	return
}

func (h *Handler) destinationToTCP(d net.Destination) *net.TCPAddr {
	var ip net.IP
	if d.Address.Family() == net.AddressFamilyDomain {
		addr := h.resolveIP(d.Address.Domain())
		if addr == nil {
			newError("failed to resolve domain: ", d.String()).AtError().WriteToLog()
			return nil
		}
		ip = addr.IP().To4()
	} else if d.Address.Family() == net.AddressFamilyIPv4 {
		ip = d.Address.IP().To4()
	} else {
		newError("failed to dial uinsupported destination: ", d.String()).AtError().WriteToLog()
		return nil
	}
	return &net.TCPAddr{
		IP:   ip,
		Port: int(d.Port),
	}
}

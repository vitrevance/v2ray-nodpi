package nodpi

import (
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/v2fly/v2ray-core/v5/common/dice"
	"golang.org/x/exp/maps"
)

type stats struct {
	requests atomic.Uint64
	failures atomic.Uint64
}

type BlockPredictor struct {
	mux     sync.RWMutex
	sniStat map[string]*stats
	allow   map[string]struct{}
}

type ConnSentinel struct {
	Conn      net.Conn
	mux       sync.Mutex
	predictor *BlockPredictor
	failed    bool
	sni       string
	rcnt      int
}

func NewBlockPredictor() *BlockPredictor {
	predictor := &BlockPredictor{sniStat: make(map[string]*stats), allow: make(map[string]struct{})}
	go predictor.runBackground()
	return predictor
}

func (p *BlockPredictor) NewReporter(conn net.Conn) *ConnSentinel {
	return &ConnSentinel{predictor: p, Conn: conn}
}

func (p *BlockPredictor) runBackground() {
	var iter uint64 = 0
	cachePath := os.Getenv("SNI_CACHE_PATH")
	if cachePath != "" {
		emptyReg := regexp.MustCompile(`^[^\s]+$`)
		p.mux.Lock()
		content, err := os.ReadFile(cachePath)
		if err != nil {
			newError("failed to read cache for adaptive SNI algorithm from path", cachePath, err).AtError().WriteToLog()
		} else {
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				if emptyReg.MatchString(line) {
					p.allow[line] = struct{}{}
				} else {
					newError("skipping invalid cache entry", line).AtWarning().WriteToLog()
				}
			}
		}
		p.mux.Unlock()
	}
	for {
		time.Sleep(time.Minute * 15)
		iter++
		p.mux.Lock()
		for sni, st := range p.sniStat {
			attempts := st.requests.Load()
			fails := st.failures.Load()
			if attempts > 50 && fails > attempts/2 {
				p.allow[sni] = struct{}{}
			}
		}
		if iter%20 == 0 {
			p.sniStat = make(map[string]*stats)
		} else {
			for sni := range p.allow {
				delete(p.sniStat, sni)
			}
		}
		p.mux.Unlock()
		if cachePath != "" {
			text := strings.Join(maps.Keys(p.allow), "\n")
			f, err := os.Create(cachePath)
			if err != nil {
				newError("failed to write adaptive SNI algorithm cache to file", cachePath, err).AtError().WriteToLog()
			} else {
				_, err := f.WriteString(text)
				if err != nil {
					newError("failed to write adaptive SNI algorithm cache to file", cachePath, err).AtError().WriteToLog()
				}
				f.Close()
			}
		}
	}
}

func (p *BlockPredictor) commitReport(s *ConnSentinel) {
	if s.sni != "" {
		p.mux.RLock()
		if _, ok := p.allow[s.sni]; ok {
			p.mux.RUnlock()
			return
		} else {
			p.mux.RUnlock()
		}
		p.mux.Lock()
		st := p.sniStat[s.sni]
		if st == nil {
			st = &stats{}
			p.sniStat[s.sni] = st
		}
		p.mux.Unlock()
		if st != nil {
			st.requests.Add(1)
			if s.failed || s.rcnt == 0 {
				st.failures.Add(1)
			}
		}
	}
}

// Whether this SNI should go through splitter or not.
func (p *BlockPredictor) PredictAllow(sni string) bool {
	p.mux.RLock()
	st := p.sniStat[sni]
	_, allowed := p.allow[sni]
	p.mux.RUnlock()

	if allowed {
		return true
	}
	if st == nil {
		return false
	}

	attempts := st.requests.Load()
	fails := st.failures.Load()
	if attempts > 2 && fails > attempts/2 {
		if dice.RollUint64()%attempts > 0 {
			return true
		}
	}

	return false
}

func (s *ConnSentinel) MarkCanceled() {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.predictor = nil
}

func (s *ConnSentinel) GetSNI() string {
	s.mux.Lock()
	defer s.mux.Unlock()
	return s.sni
}

func (s *ConnSentinel) ReportSNI(sni string) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.sni = sni
}

func (s *ConnSentinel) ReportFailure() {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.failed = true
}

func (s *ConnSentinel) Close() {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.predictor != nil {
		s.predictor.commitReport(s)
	}
	s.Conn.Close()
}

func (s *ConnSentinel) Read(buf []byte) (int, error) {
	n, err := s.Conn.Read(buf)
	s.mux.Lock()
	s.rcnt += n
	s.mux.Unlock()
	return n, err
}

func (s *ConnSentinel) Write(buf []byte) (int, error) {
	return s.Conn.Write(buf)
}

func DummyReporter(conn net.Conn) *ConnSentinel {
	return &ConnSentinel{predictor: nil, Conn: conn}
}

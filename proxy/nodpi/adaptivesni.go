package nodpi

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/v2fly/v2ray-core/v5/common/dice"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
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
	Conn      internet.Connection
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

func (p *BlockPredictor) NewReporter(conn internet.Connection) *ConnSentinel {
	return &ConnSentinel{predictor: p, Conn: conn}
}

func (p *BlockPredictor) runBackground() {
	var iter uint64 = 0
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
func (p *BlockPredictor) PredictAllow(s *ConnSentinel) bool {
	s.mux.Lock()
	sni := s.sni
	s.mux.Unlock()
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
		if dice.RollUint64()%attempts > 3 {
			s.MarkCanceled()
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

func DummyReporter(conn internet.Connection) *ConnSentinel {
	return &ConnSentinel{predictor: nil, Conn: conn}
}

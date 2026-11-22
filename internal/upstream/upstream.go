// Package upstream forwards queries to a list of resolvers with failover.
//
// Servers are tried in the configured order. A network failure or timeout
// moves on to the next server and marks the failed one down for a while,
// so later queries skip it instead of each waiting out the same timeout.
// SERVFAIL and REFUSED also move on, but do not mark the server down:
// those usually concern one domain, not the server.
package upstream

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"eventhorizon/internal/dnsmsg"
)

// DownFor is how long a server that failed is skipped.
const DownFor = 30 * time.Second

type server struct {
	addr      string
	downUntil time.Time // zero when healthy
	lastErr   error
}

type Pool struct {
	timeout time.Duration // per attempt
	downFor time.Duration
	now     func() time.Time

	mu      sync.Mutex
	servers []*server
}

// New returns a pool over addrs ("1.1.1.1:53"), most preferred first.
// timeout bounds each single attempt, not the whole exchange.
func New(addrs []string, timeout time.Duration) (*Pool, error) {
	if len(addrs) == 0 {
		return nil, errors.New("upstream: no servers given")
	}
	p := &Pool{timeout: timeout, downFor: DownFor, now: time.Now}
	for _, a := range addrs {
		if _, _, err := net.SplitHostPort(a); err != nil {
			return nil, fmt.Errorf("upstream %q: %w", a, err)
		}
		p.servers = append(p.servers, &server{addr: a})
	}
	return p, nil
}

// Result tells the caller where the answer came from, for logging.
type Result struct {
	Resp     []byte
	Server   string
	Attempts int
}

// Exchange sends msg (a query with the given ID) over proto ("udp" or
// "tcp") and returns the first usable answer.
func (p *Pool) Exchange(proto string, msg []byte, id uint16) (Result, error) {
	var (
		lastErr  error
		fallback Result // a SERVFAIL/REFUSED answer, used if nothing better comes
		res      Result
	)
	for _, s := range p.order() {
		res.Attempts++
		resp, err := exchange(proto, s.addr, msg, id, p.timeout)
		if err != nil {
			p.markDown(s, err)
			lastErr = fmt.Errorf("%s: %w", s.addr, err)
			continue
		}
		p.markUp(s)

		if rcode := resp[3] & 0x0F; rcode == dnsmsg.RcodeServFail || rcode == rcodeRefused {
			if fallback.Resp == nil {
				fallback = Result{Resp: resp, Server: s.addr}
			}
			continue
		}
		res.Resp, res.Server = resp, s.addr
		return res, nil
	}
	if fallback.Resp != nil {
		fallback.Attempts = res.Attempts
		return fallback, nil
	}
	return res, lastErr
}

const rcodeRefused = 5

// order returns healthy servers in configured order, then the ones that
// are down. When everything is down, asking a down server beats failing
// without asking anyone.
func (p *Pool) order() []*server {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	healthy := make([]*server, 0, len(p.servers))
	var down []*server
	for _, s := range p.servers {
		if now.Before(s.downUntil) {
			down = append(down, s)
		} else {
			healthy = append(healthy, s)
		}
	}
	return append(healthy, down...)
}

func (p *Pool) markDown(s *server, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s.downUntil = p.now().Add(p.downFor)
	s.lastErr = err
}

func (p *Pool) markUp(s *server) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s.downUntil = time.Time{}
	s.lastErr = nil
}

// Status describes one server for the dashboard.
type Status struct {
	Addr      string    `json:"addr"`
	Up        bool      `json:"up"`
	DownUntil time.Time `json:"down_until,omitzero"`
	LastError string    `json:"last_error,omitempty"`
}

func (p *Pool) Status() []Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	out := make([]Status, len(p.servers))
	for i, s := range p.servers {
		out[i] = Status{Addr: s.addr, Up: !now.Before(s.downUntil)}
		if !out[i].Up {
			out[i].DownUntil = s.downUntil
			if s.lastErr != nil {
				out[i].LastError = s.lastErr.Error()
			}
		}
	}
	return out
}

// exchange does one round trip to one server. The original bytes are sent
// untouched, so EDNS options and everything else survive.
func exchange(proto, addr string, msg []byte, id uint16, timeout time.Duration) ([]byte, error) {
	c, err := net.DialTimeout(proto, addr, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	if proto == "tcp" {
		if err := dnsmsg.WriteFramed(c, msg); err != nil {
			return nil, err
		}
		resp, err := dnsmsg.ReadFramed(c)
		if err != nil {
			return nil, err
		}
		if got, ok := dnsmsg.ResponseID(resp); !ok || got != id || len(resp) < 12 {
			return nil, errors.New("reply does not match the query")
		}
		return resp, nil
	}

	if _, err := c.Write(msg); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		// Ignore stray or spoofed packets: a reply must carry our ID and
		// at least a full header.
		if got, ok := dnsmsg.ResponseID(buf[:n]); ok && got == id && n >= 12 {
			return buf[:n], nil
		}
	}
}

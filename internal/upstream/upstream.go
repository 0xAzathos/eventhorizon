// Package upstream forwards queries to a list of resolvers with failover,
// over plain DNS or DNS over TLS.
//
// Server syntax:
//
//	1.1.1.1:53                     plain DNS (port 53 if left out)
//	tls://1.1.1.1#cloudflare-dns.com  DNS over TLS (port 853 if left out);
//	                               the name after # is checked against the
//	                               server's certificate
//
// Servers must be IP addresses: resolving a hostname would need DNS, and
// eventhorizon is the DNS. The certificate name goes after the #.
//
// Servers are tried in the configured order. A network failure or timeout
// moves on to the next server and marks the failed one down for a while,
// so later queries skip it instead of each waiting out the same timeout.
// SERVFAIL and REFUSED also move on, but do not mark the server down:
// those usually concern one domain, not the server.
package upstream

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"eventhorizon/internal/dnsmsg"
)

// DownFor is how long a server that failed is skipped.
const DownFor = 30 * time.Second

// DNS over TLS connections are kept open between queries, because a TLS
// handshake costs several round trips. Servers close idle connections
// after a while, so ones idle longer than this are not reused.
const (
	maxIdleConns = 4
	maxIdleTime  = 10 * time.Second
)

type idleConn struct {
	conn  net.Conn
	since time.Time
}

type server struct {
	spec string // as configured, for display
	addr string // ip:port
	tls  *tls.Config

	// Guarded by Pool.mu.
	downUntil time.Time
	lastErr   error

	idleMu sync.Mutex
	idle   []idleConn
}

type Pool struct {
	timeout time.Duration // per attempt
	downFor time.Duration
	now     func() time.Time

	mu      sync.Mutex
	servers []*server
}

// New returns a pool over specs, most preferred first. timeout bounds each
// single attempt, not the whole exchange.
func New(specs []string, timeout time.Duration) (*Pool, error) {
	if len(specs) == 0 {
		return nil, errors.New("upstream: no servers given")
	}
	p := &Pool{timeout: timeout, downFor: DownFor, now: time.Now}
	for _, spec := range specs {
		s, err := parseSpec(spec)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: %w", spec, err)
		}
		p.servers = append(p.servers, s)
	}
	return p, nil
}

func parseSpec(spec string) (*server, error) {
	rest, isTLS := strings.CutPrefix(spec, "tls://")
	rest, name, _ := strings.Cut(rest, "#")

	port := "53"
	if isTLS {
		port = "853"
	}
	host := rest
	if h, p, err := net.SplitHostPort(rest); err == nil {
		host, port = h, p
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("bad port %q", port)
		}
	}
	// An IPv6 address without a port keeps its brackets: [2606:4700::1111]
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, errors.New("must be an IP address; for TLS put the certificate name after #, as in tls://1.1.1.1#cloudflare-dns.com")
	}
	if name != "" && !isTLS {
		return nil, errors.New("#name only applies to tls:// servers")
	}

	s := &server{spec: spec, addr: net.JoinHostPort(ip.String(), port)}
	if isTLS {
		if name == "" {
			name = ip.String() // the certificate must then list the IP itself
		}
		s.tls = &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12}
	}
	return s, nil
}

// Result tells the caller where the answer came from, for logging.
type Result struct {
	Resp     []byte
	Server   string
	Attempts int
}

// Exchange sends msg (a query with the given ID) and returns the first
// usable answer. proto is how the client asked ("udp" or "tcp"); plain
// servers are asked the same way, TLS servers always over TLS.
func (p *Pool) Exchange(proto string, msg []byte, id uint16) (Result, error) {
	var (
		lastErr  error
		fallback Result // a SERVFAIL/REFUSED answer, used if nothing better comes
		res      Result
	)
	for _, s := range p.order() {
		res.Attempts++
		var resp []byte
		var err error
		if s.tls != nil {
			resp, err = s.exchangeTLS(msg, id, p.timeout)
		} else {
			resp, err = exchangePlain(proto, s.addr, msg, id, p.timeout)
		}
		if err != nil {
			p.markDown(s, err)
			lastErr = fmt.Errorf("%s: %w", s.spec, err)
			continue
		}
		p.markUp(s)

		if rcode := resp[3] & 0x0F; rcode == dnsmsg.RcodeServFail || rcode == rcodeRefused {
			if fallback.Resp == nil {
				fallback = Result{Resp: resp, Server: s.spec}
			}
			continue
		}
		res.Resp, res.Server = resp, s.spec
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
	Encrypted bool      `json:"encrypted"`
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
		out[i] = Status{Addr: s.addr, Encrypted: s.tls != nil, Up: !now.Before(s.downUntil)}
		if !out[i].Up {
			out[i].DownUntil = s.downUntil
			if s.lastErr != nil {
				out[i].LastError = s.lastErr.Error()
			}
		}
	}
	return out
}

// Close drops all idle TLS connections.
func (p *Pool) Close() {
	for _, s := range p.servers {
		s.idleMu.Lock()
		for _, ic := range s.idle {
			ic.conn.Close()
		}
		s.idle = nil
		s.idleMu.Unlock()
	}
}

// exchangeTLS does one round trip over DNS over TLS (RFC 7858): the same
// length prefixed messages as DNS over TCP, inside a TLS connection.
func (s *server) exchangeTLS(msg []byte, id uint16, timeout time.Duration) ([]byte, error) {
	if conn := s.takeIdle(); conn != nil {
		resp, err := roundTrip(conn, msg, id, timeout)
		if err == nil {
			s.putIdle(conn)
			return resp, nil
		}
		// The server probably closed the idle connection; try once more
		// on a fresh one before calling this server down.
		conn.Close()
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", s.addr, s.tls)
	if err != nil {
		return nil, err
	}
	resp, err := roundTrip(conn, msg, id, timeout)
	if err != nil {
		conn.Close()
		return nil, err
	}
	s.putIdle(conn)
	return resp, nil
}

func roundTrip(conn net.Conn, msg []byte, id uint16, timeout time.Duration) ([]byte, error) {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if err := dnsmsg.WriteFramed(conn, msg); err != nil {
		return nil, err
	}
	resp, err := dnsmsg.ReadFramed(conn)
	if err != nil {
		return nil, err
	}
	if got, ok := dnsmsg.ResponseID(resp); !ok || got != id || len(resp) < 12 {
		return nil, errors.New("reply does not match the query")
	}
	return resp, nil
}

// takeIdle returns the most recently used idle connection, discarding
// any that sat too long.
func (s *server) takeIdle() net.Conn {
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	for len(s.idle) > 0 {
		ic := s.idle[len(s.idle)-1]
		s.idle = s.idle[:len(s.idle)-1]
		if time.Since(ic.since) < maxIdleTime {
			return ic.conn
		}
		ic.conn.Close()
	}
	return nil
}

func (s *server) putIdle(conn net.Conn) {
	s.idleMu.Lock()
	defer s.idleMu.Unlock()
	if len(s.idle) >= maxIdleConns {
		conn.Close()
		return
	}
	s.idle = append(s.idle, idleConn{conn, time.Now()})
}

// exchangePlain does one round trip over plain UDP or TCP. The original
// bytes are sent untouched, so EDNS options and everything else survive.
func exchangePlain(proto, addr string, msg []byte, id uint16, timeout time.Duration) ([]byte, error) {
	c, err := net.DialTimeout(proto, addr, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	if proto == "tcp" {
		return roundTrip(c, msg, id, timeout)
	}

	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
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

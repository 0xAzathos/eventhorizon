// Package guard decides which clients may use the server: an allow list of
// networks, and a per client rate limit. It is what keeps eventhorizon from
// becoming an open resolver when it listens on a network address.
package guard

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Named groups of networks for -allow-clients.
var groups = map[string][]string{
	"loopback": {"127.0.0.0/8", "::1/128"},
	// Private ranges home and office networks use: RFC 1918, IPv6 unique
	// local addresses (RFC 4193), and link local addresses.
	"private": {
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"fc00::/7",
		"169.254.0.0/16", "fe80::/10",
	},
	// Everyone. Only for testing behind a firewall; this is an open resolver.
	"any": {"0.0.0.0/0", "::/0"},
}

// ACL is a list of networks allowed to send queries.
type ACL struct {
	prefixes []netip.Prefix
	open     bool // contains "any"
}

// ParseACL reads a comma separated list of CIDRs, single addresses and the
// group names loopback, private and any.
func ParseACL(spec string) (*ACL, error) {
	acl := &ACL{}
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if g, ok := groups[item]; ok {
			acl.open = acl.open || item == "any"
			for _, cidr := range g {
				acl.prefixes = append(acl.prefixes, netip.MustParsePrefix(cidr))
			}
			continue
		}
		if p, err := netip.ParsePrefix(item); err == nil {
			acl.prefixes = append(acl.prefixes, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(item); err == nil {
			acl.prefixes = append(acl.prefixes, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			continue
		}
		return nil, fmt.Errorf("allow-clients: %q is not a network, address or group (loopback, private, any)", item)
	}
	if len(acl.prefixes) == 0 {
		return nil, fmt.Errorf("allow-clients: empty list would refuse everyone")
	}
	return acl, nil
}

// Open reports whether the list allows every address.
func (a *ACL) Open() bool { return a.open }

// Allows reports whether addr may send queries. IPv4 clients on a dual
// stack socket arrive as ::ffff:a.b.c.d; they are matched as plain IPv4.
func (a *ACL) Allows(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range a.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Limiter is a token bucket per client: each client may send rate queries
// per second on average, and up to burst in a row. Buckets of clients that
// went quiet are forgotten, so memory stays small.
type Limiter struct {
	rate  float64
	burst float64

	mu        sync.Mutex
	buckets   map[netip.Addr]*bucket
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// idleAfter is how long a full bucket is kept before it is forgotten. A
// forgotten client starts again with a full bucket, which is exactly what
// a kept one would have by then.
const idleAfter = time.Minute

func NewLimiter(rate, burst float64) *Limiter {
	return &Limiter{rate: rate, burst: burst, buckets: make(map[netip.Addr]*bucket)}
}

// Allow takes one token for addr, and reports whether there was one.
func (l *Limiter) Allow(addr netip.Addr, now time.Time) bool {
	addr = addr.Unmap()
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastSweep) > idleAfter {
		l.sweep(now)
	}
	b, ok := l.buckets[addr]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[addr] = b
	}
	// Refill for the time since the last query, up to the burst size.
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *Limiter) sweep(now time.Time) {
	for addr, b := range l.buckets {
		if now.Sub(b.last) > idleAfter {
			delete(l.buckets, addr)
		}
	}
	l.lastSweep = now
}

// Tracked reports how many clients currently have a bucket.
func (l *Limiter) Tracked() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// Reporter decides when a turned away client is worth a log line: once per
// client per interval, so a flood cannot flood the log as well.
type Reporter struct {
	every time.Duration
	mu    sync.Mutex
	last  map[netip.Addr]time.Time
}

func NewReporter(every time.Duration) *Reporter {
	return &Reporter{every: every, last: make(map[netip.Addr]time.Time)}
}

func (r *Reporter) Should(addr netip.Addr, now time.Time) bool {
	addr = addr.Unmap()
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.last[addr]; ok && now.Sub(t) < r.every {
		return false
	}
	if len(r.last) > 10000 { // keep memory bounded under a spoofed flood
		for a, t := range r.last {
			if now.Sub(t) >= r.every {
				delete(r.last, a)
			}
		}
	}
	r.last[addr] = now
	return true
}

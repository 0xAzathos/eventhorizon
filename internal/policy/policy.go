// Package policy decides whether a domain is blocked.
//
// Matching includes parent domains: if "tracker.com" is listed, then
// "ads.tracker.com" and "x.y.tracker.com" are matched too. The allowlist
// always wins over the blocklist.
package policy

import (
	"bufio"
	"io"
	"net"
	"strings"
)

// Set is a collection of domains with parent domain matching.
// A nil *Set is valid and matches nothing.
type Set struct {
	domains map[string]struct{}
}

func NewSet() *Set {
	return &Set{domains: make(map[string]struct{})}
}

// Hostnames that appear in hosts files but are not things to block.
var ignored = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true,
	"broadcasthost": true, "ip6-localhost": true, "ip6-loopback": true,
	"ip6-localnet": true, "ip6-mcastprefix": true, "ip6-allnodes": true,
	"ip6-allrouters": true, "ip6-allhosts": true,
}

func normalize(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

// Add inserts a domain. Returns false if it was empty, ignored, or already
// present.
func (s *Set) Add(domain string) bool {
	d := normalize(domain)
	if d == "" || ignored[d] || net.ParseIP(d) != nil {
		return false
	}
	if _, dup := s.domains[d]; dup {
		return false
	}
	s.domains[d] = struct{}{}
	return true
}

func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.domains)
}

// Match checks name and each of its parents, most specific first.
// Returns the entry that matched.
func (s *Set) Match(name string) (string, bool) {
	if s == nil {
		return "", false
	}
	for {
		if _, ok := s.domains[name]; ok {
			return name, true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return "", false
		}
		name = name[i+1:]
	}
}

// Load reads a hosts file ("0.0.0.0 ads.example.com") or a plain domain
// list (one domain per line). Comments start with '#'. Returns how many new
// domains were added.
func (s *Set) Load(r io.Reader) (int, error) {
	added := 0
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		// Hosts format starts with an IP; the rest of the line are names.
		if net.ParseIP(fields[0]) != nil {
			fields = fields[1:]
		}
		for _, f := range fields {
			if s.Add(f) {
				added++
			}
		}
	}
	return added, sc.Err()
}

// Decision is the outcome for one name, with the rule that caused it.
type Decision struct {
	Blocked bool
	Rule    string // the matching list entry, "" if nothing matched
}

type Policy struct {
	Block *Set
	Allow *Set
}

func (p *Policy) Decide(name string) Decision {
	if rule, ok := p.Allow.Match(name); ok {
		return Decision{Blocked: false, Rule: rule}
	}
	if rule, ok := p.Block.Match(name); ok {
		return Decision{Blocked: true, Rule: rule}
	}
	return Decision{}
}

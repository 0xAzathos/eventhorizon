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
		raw := strings.TrimSpace(sc.Text())
		if skipLine(raw) {
			continue
		}
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
			if s.Add(cleanEntry(f)) {
				added++
			}
		}
	}
	return added, sc.Err()
}

// skipLne reports lines that hold no domains: adblock comments ("!"),
// headers ("[Adblock Plus 2.0]") and element hiding rules such as
// "example.com##.banner". Those hide part of a page; reading them as
// domains would block example.com itself.
func skipLine(line string) bool {
	if strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
		return true
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return true
	}
	first := fields[0]
	return strings.Contains(first, "#") && !strings.HasPrefix(first, "#")
}

// cleanEntry turns one list entry into a plain domain, or "" to skip it.
// Besides plain domains it understands two ways lists write "this domain
// and al its subdomains": the adblock style "||example.com^" and the
// wildcard style "*.example.com". Adblock rules with a path or options
// ("||example.com/ad.js^", "||example.com^$third-party") only block some
// requests, so a DNS blocker must skip them rather than block the whole
// domain. So must any other entry with pattern characters left in it.
func cleanEntry(f string) string {
	if rest, ok := strings.CutPrefix(f, "||"); ok {
		domain, ok := strings.CutSuffix(rest, "^")
		if !ok {
			return ""
		}
		f = domain
	} else {
		f = strings.TrimPrefix(f, "*.")
	}
	if strings.ContainsAny(f, "*/$^|") {
		return ""
	}
	return f
}

// Decision is the outcome for one name, with the rule that caused it.
type Decision struct {
	Blocked bool
	Rule    string // the matching entry, "" if nothing matched
	Mine    bool   // the rule is one of the user's own (UserAllow/UserBlock)
}

// Policy decides in this order, first match wins:
//
//  1. UserAllow  your own allow rules
//  2. UserBlock  your own block rules
//  3. Allow      the allowlist file
//  4. Block      the blocklists
//
// Your own rules beat the lists in both directions: they are the most
// recent, most explicit choice.
type Policy struct {
	Block     *Set
	Allow     *Set
	UserAllow *Set
	UserBlock *Set
}

func (p *Policy) Decide(name string) Decision {
	if rule, ok := p.UserAllow.Match(name); ok {
		return Decision{Rule: rule, Mine: true}
	}
	if rule, ok := p.UserBlock.Match(name); ok {
		return Decision{Blocked: true, Rule: rule, Mine: true}
	}
	if rule, ok := p.Allow.Match(name); ok {
		return Decision{Rule: rule}
	}
	if rule, ok := p.Block.Match(name); ok {
		return Decision{Blocked: true, Rule: rule}
	}
	return Decision{}
}

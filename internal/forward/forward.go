// Package forward sends queries for chosen zones, such as your home
// network's "lan" or "home.arpa", to a chosen server instead of the upstreams.
// Your router knows the names of your devices; Cloudflare does not.
package forward

import (
	"fmt"
	"net/netip"
	"strings"
)

// Table maps zones to the server that answers for them.
type Table struct {
	zones map[string]netip.AddrPort
}

// Parse reads rules like "lan=192.168.1.1.,home.arpa=192.168.1.1:5353".
// The port defaults to 53. An empty spec gives an empty table.
func Parse(spec string) (*Table, error) {
	t := &Table{zones: map[string]netip.AddrPort{}}
	for _, rule := range strings.Split(spec, ",") {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}
		zone, server, ok := strings.Cut(rule, "=")
		if !ok {
			return nil, fmt.Errorf("forward rule %q: want zone=server", rule)
		}
		zone = normalize(zone)
		if zone == "" || strings.ContainsAny(zone, "*/ ") {
			return nil, fmt.Errorf("forward rule %q: bad zone", rule)
		}
		addr, err := parseServer(strings.TrimSpace(server))
		if err != nil {
			return nil, fmt.Errorf("forward rule %q: %w", rule, err)
		}
		if _, dup := t.zones[zone]; dup {
			return nil, fmt.Errorf("forward rule %q: zone %s is given twice", rule, zone)
		}
		t.zones[zone] = addr
	}
	return t, nil
}

// parseServer accepts "192.168.1.1", "192.168.1.1:5353", "fd00::1" or
// "[fd00::1]:5353". Only IP addresses: a name would need DNS to find
// the server that answers DNS.
func parseServer(s string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("server %q is not an IP address", s)
	}
	return netip.AddrPortFrom(addr, 53), nil
}

func normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// Lookup returns the server for name: the rule for the longest zone that
// is the name itself or one of its parents. "nas.lan" and "lan" match
// the zone "lan"; "plan" does not.
func (t *Table) Lookup(name string) (netip.AddrPort, bool) {
	if t == nil {
		return netip.AddrPort{}, false
	}
	name = normalize(name)
	for {
		if ap, ok := t.zones[name]; ok {
			return ap, true
		}
		_, parent, ok := strings.Cut(name, ".")
		if !ok {
			return netip.AddrPort{}, false
		}
		name = parent
	}
}

// Servers list each server a rule points at, once
func (t *Table) Servers() []netip.AddrPort {
	if t == nil {
		return nil
	}
	seen := map[netip.AddrPort]bool{}
	var out []netip.AddrPort
	for _, ap := range t.zones {
		if !seen[ap] {
			seen[ap] = true
			out = append(out, ap)
		}
	}
	return out
}

// Len reports how many zones have a rule.
func (t *Table) Len() int {
	if t == nil {
		return 0
	}
	return len(t.zones)
}

package server

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/0xAzathos/eventhorizon/internal/dnsmsg"
)

// Some names only mean something inside your own network. Asking the
// internet about them can never give a useful answer, and it tells the
// upstream what your network looks like. eventhorizon answers them itself
// with "no such name", unless a -forward rule send the zone to your router.
var localOnlyZones = []string{
	"local",     // mDNS: devices answer these themselves (RFC 6762)
	"invalid",   // never exists, by definition (RFC 6761)
	"test",      // reserved for testing (RFC 6761)
	"home.arpa", // home networks (RFC 8375)
}

// localOnly reports whether a query must never leave the network.
// Besides teh zones above, that is a reverse lookup of a private address
// (which devices is 192.168.10.20?), and an address lookup for a name without a dot,
// such as "nas" or "printer": no internet domain looks like that.
// Other types are left alone, because tools do ask about bare names like "com".
func localOnly(name string, qtype uint16) bool {
	if name == "" {
		return false // the root
	}
	if !strings.Contains(name, ".") && (qtype == dnsmsg.TypeA || qtype == dnsmsg.TypeAAAA) {
		return true
	}
	if addr, ok := reverseAddr(name); ok && privateAddr(addr) {
		return true
	}
	for _, zone := range localOnlyZones {
		if name == zone || strings.HasSuffix(name, "."+zone) {
			return true
		}
	}
	return false
}

// reverseAddr turns a full reverse lookup name back into the address it asks about.
// IPv4 writes the four numbers last first: "203.10.168.192.in-addr.arpa" is 192.168.10.203.
// IPv6 writes all 32 hex digits last first, one per label, under "ip6.arpa".
func reverseAddr(name string) (netip.Addr, bool) {
	if rest, ok := strings.CutSuffix(name, ".in-addr.arpa"); ok {
		labels := strings.Split(rest, ".")
		if len(labels) != 4 {
			return netip.Addr{}, false
		}
		slices.Reverse(labels)
		addr, err := netip.ParseAddr(strings.Join(labels, "."))
		return addr, err == nil && addr.Is4()
	}
	if rest, ok := strings.CutSuffix(name, ".ip6.arpa"); ok {
		digits := strings.Split(rest, ".")
		if len(digits) != 32 {
			return netip.Addr{}, false
		}
		var b [16]byte
		for i, d := range digits {
			v, err := strconv.ParseUint(d, 16, 8)
			if err != nil || len(d) != 1 {
				return netip.Addr{}, false
			}
			pos := 31 - i // digits[0] is the last hex digit of the address
			if pos%2 == 0 {
				b[pos/2] |= byte(v) << 4 // first digit of a byte: high half
			} else {
				b[pos/2] |= byte(v)
			}
		}
		return netip.AddrFrom16(b), true
	}
	return netip.Addr{}, false
}

// sharedSpace is carrier grade NAT, also used by Tailscale and some VPNs
// (RFC 6598). Like private ranges, it means nothung on the internet.
var sharedSpace = netip.MustParsePrefix("100.64.0.0/10")

// privateAddr reports addresses only your own network can name.
func privateAddr(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() ||
		a.IsUnspecified() || sharedSpace.Contains(a)
}

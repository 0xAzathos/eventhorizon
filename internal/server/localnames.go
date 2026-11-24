package server

import (
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

func localOnly(name string, qtype uint16) bool {
	if name == "" {
		return false // the root
	}
	if !strings.Contains(name, ".") && (qtype == dnsmsg.TypeA || qtype == dnsmsg.TypeAAAA) {
		return true
	}
	for _, zone := range localOnlyZones {
		if name == zone || strings.HasSuffix(name, "."+zone) {
			return true
		}
	}
	return false
}

package server

import (
	"net"
	"net/netip"
	"time"

	"github.com/0xAzathos/eventhorizon/internal/guard"
)

// Who may ask, and how often. Checked before any parsing, so turned away
// traffic costs almost nothing.
//
// Over UDP a turned away query gets no reply at all: the sender address of
// a UDP packet can be forged, and even a small "REFUSED" would then be sent
// to whoever was impersonated. Over TCP, where addresses cannot be forged,
// strangers have their connection closed and rate limited clients get
// REFUSED.

// clientAddr extracts the client's IP address.
func clientAddr(a net.Addr) netip.Addr {
	switch a := a.(type) {
	case *net.UDPAddr:
		return a.AddrPort().Addr().Unmap()
	case *net.TCPAddr:
		return a.AddrPort().Addr().Unmap()
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// allowedClient applies the allow list.
func (s *Server) allowedClient(ip netip.Addr) bool {
	if s.ACL == nil || s.ACL.Allows(ip) {
		return true
	}
	s.turnedAway(ip, "not in allow-clients")
	return false
}

// withinRate applies the rate limit.
func (s *Server) withinRate(ip netip.Addr) bool {
	if s.Limit == nil || s.Limit.Allow(ip, time.Now()) {
		return true
	}
	s.turnedAway(ip, "rate limited")
	return false
}

// turnedAway counts every refusal, but logs each client at most once per
// minute so a flood cannot flood the log too.
func (s *Server) turnedAway(ip netip.Addr, reason string) {
	s.Stats.RecordRefused()
	s.reportsOnce.Do(func() { s.reports = guard.NewReporter(time.Minute) })
	if s.reports.Should(ip, time.Now()) {
		s.Log.Warn("client turned away", "client", ip.String(), "reason", reason)
	}
}

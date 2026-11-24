package server

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/0xAzathos/eventhorizon/internal/dnsmsg"
	"github.com/0xAzathos/eventhorizon/internal/forward"
	"github.com/0xAzathos/eventhorizon/internal/policy"
	"github.com/0xAzathos/eventhorizon/internal/upstream"
)

func TestLocalOnly(t *testing.T) {
	for _, tc := range []struct {
		name  string
		qtype uint16
		want  bool
	}{
		{"printer.local", dnsmsg.TypeA, true},
		{"local", dnsmsg.TypeA, true},
		{"x.domain_not_set.invalid", dnsmsg.TypeAAAA, true},
		{"nas.home.arpa", dnsmsg.TypeA, true},
		{"nas", dnsmsg.TypeA, true},
		{"nas", dnsmsg.TypeAAAA, true},
		{"com", dnsmsg.TypeNS, false}, // bare names are fine for other types
		{"", dnsmsg.TypeNS, false},    // the root
		{"example.com", dnsmsg.TypeA, false},
		{"notlocal", dnsmsg.TypeMX, false},
		{"mylocal.com", dnsmsg.TypeA, false}, // whole labels only
		{"203.10.168.192.in-addr.arpa", dnsmsg.TypePTR, true},
		{"1.0.64.100.in-addr.arpa", dnsmsg.TypePTR, true}, // shared space
		{"1.1.1.1.in-addr.arpa", dnsmsg.TypePTR, false},   // public
		{"168.192.in-addr.arpa", dnsmsg.TypeSOA, false},   // not one address
	} {
		if got := localOnly(tc.name, tc.qtype); got != tc.want {
			t.Errorf("localOnly(%q, %d) = %v, want %v", tc.name, tc.qtype, got, tc.want)
		}
	}
}

func TestLocalNamesStayLocal(t *testing.T) {
	up, upHits := fakeUpstream(t)
	router, routerHits := fakeUpstream(t)
	table, err := forward.Parse("home.arpa=" + router)
	if err != nil {
		t.Fatal(err)
	}
	lan := newPool(t, router)

	srv := &Server{
		Upstream: newPool(t, up),
		Local: func(name string) *upstream.Pool {
			if _, ok := table.Lookup(name); ok {
				return lan
			}
			return nil
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	srv.SetPolicy(&policy.Policy{Block: policy.NewSet()})
	pc, ln := listenBoth(t)
	go srv.ServeUDP(pc)
	go srv.ServeTCP(ln)
	addr := pc.LocalAddr().String()

	for i, name := range []string{"printer.local", "nas", "a.b.invalid"} {
		resp := exchangeUDP(t, addr, query(uint16(i+1), name, dnsmsg.TypeA))
		if rcode := resp[3] & 0x0F; rcode != dnsmsg.RcodeNXDomain {
			t.Errorf("%s: rcode %d, want NXDOMAIN", name, rcode)
		}
		if qd := binary.BigEndian.Uint16(resp[4:]); qd != 1 {
			t.Errorf("%s: answer has %d questions, want the question echoed", name, qd)
		}
	}
	if n := upHits.udp.Load(); n != 0 {
		t.Errorf("upstream got %d local names", n)
	}

	// A zone with a -forward rule goes to the router instead.
	exchangeUDP(t, addr, query(0, "nas.home.arpa", dnsmsg.TypeA))
	if routerHits.udp.Load() != 1 || upHits.udp.Load() != 0 {
		t.Errorf("nas.home.arpa: router got %d, upstream got %d; want 1 and 0", routerHits.udp.Load(), upHits.udp.Load())
	}
}

func TestReverseAddr(t *testing.T) {
	for name, want := range map[string]string{
		"203.10.168.192.in-addr.arpa": "192.168.10.203",
		"1.0.0.127.in-addr.arpa":      "127.0.0.1",
		// fd00::1 is f d 0 0, 27 zeros, 1; written last digit first.
		"1." + strings.Repeat("0.", 29) + "d.f.ip6.arpa":  "fd00::1",
		"1." + strings.Repeat("0.", 29) + "0.2.ip6.arpa":  "2000::1",
		"10.168.192.in-addr.arpa":                         "", // three numbers
		"300.10.168.192.in-addr.arpa":                     "", // not a byte
		"1.0.ip6.arpa":                                    "", // too few digits
		"1." + strings.Repeat("0.", 29) + "dd.f.ip6.arpa": "", // two digits in a label
		"example.com":                                     "",
	} {
		got, ok := reverseAddr(name)
		if want == "" {
			if ok {
				t.Errorf("reverseAddr(%q) = %v, want no address", name, got)
			}
			continue
		}
		if !ok || got != netip.MustParseAddr(want) {
			t.Errorf("reverseAddr(%q) = %v %v, want %s", name, got, ok, want)
		}
	}
}

func TestPrivateAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"192.168.10.203": true,
		"10.64.0.1":      true,
		"172.16.0.1":     true,
		"100.101.1.2":    true, // Tailscale
		"127.0.0.1":      true,
		"169.254.1.1":    true,
		"fd00::1":        true,
		"fe80::1":        true,
		"1.1.1.1":        false,
		"172.32.0.1":     false, // just outside 172.16.0.0/12
		"2000::1":        false,
	} {
		if got := privateAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("privateAddr(%s) = %v, want %v", addr, got, want)
		}
	}
}

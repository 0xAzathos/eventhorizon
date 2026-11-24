package server

import (
	"encoding/binary"
	"io"
	"log/slog"
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

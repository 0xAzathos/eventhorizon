package guard

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestDefaultACL(t *testing.T) {
	acl, err := ParseACL("loopback,private")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"127.0.0.1":           true,
		"::1":                 true,
		"192.168.1.20":        true,
		"10.1.2.3":            true,
		"172.16.0.1":          true,
		"172.31.255.254":      true,
		"fd12:3456::1":        true,
		"fe80::1":             true,
		"::ffff:192.168.1.20": true, // IPv4 client on a dual stack socket
		"172.32.0.1":          false,
		"8.8.8.8":             false,
		"100.64.0.1":          false, // carrier NAT space is not "private"
		"2001:db8::1":         false,
		"::ffff:8.8.8.8":      false,
	}
	for a, want := range cases {
		if got := acl.Allows(addr(a)); got != want {
			t.Errorf("%s: allowed=%v, want %v", a, got, want)
		}
	}
	if acl.Open() {
		t.Error("default list reported as open")
	}
}

func TestCustomACL(t *testing.T) {
	acl, err := ParseACL("192.168.1.0/24, 100.64.0.0/10, 203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	for a, want := range map[string]bool{
		"192.168.1.77": true, "192.168.2.1": false,
		"100.101.5.6": true, "203.0.113.9": true, "203.0.113.10": false,
	} {
		if got := acl.Allows(addr(a)); got != want {
			t.Errorf("%s: allowed=%v, want %v", a, got, want)
		}
	}
}

func TestACLAny(t *testing.T) {
	acl, _ := ParseACL("any")
	if !acl.Open() || !acl.Allows(addr("8.8.8.8")) || !acl.Allows(addr("2001:db8::1")) {
		t.Error("any should allow everyone and report open")
	}
}

func TestACLErrors(t *testing.T) {
	for _, bad := range []string{"", " , ", "lan", "192.168.1.0/33", "not-an-ip"} {
		if _, err := ParseACL(bad); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}

func TestLimiterBurstThenRate(t *testing.T) {
	l := NewLimiter(10, 20) // 10 per second, bursts of 20
	c := addr("192.168.1.5")

	for i := range 20 {
		if !l.Allow(c, t0) {
			t.Fatalf("query %d refused inside the burst", i+1)
		}
	}
	if l.Allow(c, t0) {
		t.Fatal("21st query in the same instant allowed")
	}
	// Half a second later, 5 tokens have come back.
	now := t0.Add(500 * time.Millisecond)
	allowed := 0
	for range 10 {
		if l.Allow(c, now) {
			allowed++
		}
	}
	if allowed != 5 {
		t.Errorf("allowed %d after 0.5s, want 5", allowed)
	}
}

func TestLimiterIsPerClient(t *testing.T) {
	l := NewLimiter(1, 1)
	if !l.Allow(addr("10.0.0.1"), t0) || l.Allow(addr("10.0.0.1"), t0) {
		t.Fatal("first client not limited")
	}
	if !l.Allow(addr("10.0.0.2"), t0) {
		t.Error("second client affected by the first")
	}
	// The same client, written as IPv4 mapped IPv6, shares the bucket.
	if l.Allow(addr("::ffff:10.0.0.1"), t0) {
		t.Error("mapped address got a fresh bucket")
	}
}

func TestLimiterForgetsIdleClients(t *testing.T) {
	l := NewLimiter(100, 100)
	for i := range 50 {
		l.Allow(addr(fmt.Sprintf("10.0.0.%d", i)), t0)
	}
	l.Allow(addr("10.0.1.1"), t0.Add(2*time.Minute)) // triggers a sweep
	if n := l.Tracked(); n != 1 {
		t.Errorf("tracked %d clients after they went idle, want 1", n)
	}
}

func TestReporterOncePerInterval(t *testing.T) {
	r := NewReporter(time.Minute)
	c := addr("8.8.8.8")
	if !r.Should(c, t0) || r.Should(c, t0.Add(30*time.Second)) {
		t.Error("reported twice within the interval")
	}
	if !r.Should(c, t0.Add(61*time.Second)) {
		t.Error("not reported again after the interval")
	}
	if !r.Should(addr("8.8.4.4"), t0) {
		t.Error("another client was silenced")
	}
}

package policy

import (
	"strings"
	"testing"
)

const hostsFile = `
# Title: example blocklist
127.0.0.1 localhost
::1 ip6-localhost ip6-loopback
0.0.0.0 0.0.0.0

0.0.0.0 tracker.com
0.0.0.0 ADS.Example.org.   # trailing dot and caps
0.0.0.0 a.one b.two
0.0.0.0 tracker.com
`

func TestLoadHosts(t *testing.T) {
	s := NewSet()
	n, err := s.Load(strings.NewReader(hostsFile))
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 || s.Len() != 4 {
		t.Fatalf("added %d, len %d, want 4", n, s.Len())
	}
	for _, d := range []string{"tracker.com", "ads.example.org", "a.one", "b.two"} {
		if _, ok := s.Match(d); !ok {
			t.Errorf("%s not loaded", d)
		}
	}
	if _, ok := s.Match("localhost"); ok {
		t.Error("localhost should be ignored")
	}
}

func TestLoadPlainList(t *testing.T) {
	s := NewSet()
	n, _ := s.Load(strings.NewReader("evil.net\n# comment\nbad.io\n"))
	if n != 2 {
		t.Fatalf("added %d", n)
	}
}

func TestParentMatching(t *testing.T) {
	s := NewSet()
	s.Add("tracker.com")

	cases := map[string]bool{
		"tracker.com":      true,
		"ads.tracker.com":  true,
		"x.y.tracker.com":  true,
		"nottracker.com":   false,
		"tracker.com.evil": false,
		"com":              false,
	}
	for name, want := range cases {
		rule, got := s.Match(name)
		if got != want {
			t.Errorf("%s: matched=%v, want %v", name, got, want)
		}
		if got && rule != "tracker.com" {
			t.Errorf("%s: rule=%q", name, rule)
		}
	}
}

func TestAllowWins(t *testing.T) {
	block, allow := NewSet(), NewSet()
	block.Add("example.com")
	allow.Add("good.example.com")
	p := Policy{Block: block, Allow: allow}

	if d := p.Decide("ads.example.com"); !d.Blocked || d.Rule != "example.com" {
		t.Errorf("ads: %+v", d)
	}
	if d := p.Decide("cdn.good.example.com"); d.Blocked || d.Rule != "good.example.com" {
		t.Errorf("good: %+v", d)
	}
	if d := p.Decide("other.org"); d.Blocked || d.Rule != "" {
		t.Errorf("other: %+v", d)
	}
}

func TestNilAllowlist(t *testing.T) {
	block := NewSet()
	block.Add("x.com")
	p := Policy{Block: block}
	if !p.Decide("x.com").Blocked {
		t.Error("expected block with nil allowlist")
	}
}

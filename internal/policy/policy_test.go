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

func TestUserRulesBeatLists(t *testing.T) {
	lists, file := NewSet(), NewSet()
	lists.Add("tracker.com")
	lists.Add("ads.example")
	file.Add("cdn.example")
	userAllow, userBlock := NewSet(), NewSet()
	userAllow.Add("good.tracker.com") // unblock one subdomain of a listed tracker
	userBlock.Add("cdn.example")      // block something the allowlist file allows
	p := Policy{Block: lists, Allow: file, UserAllow: userAllow, UserBlock: userBlock}

	cases := []struct {
		name    string
		blocked bool
		rule    string
		mine    bool
	}{
		{"good.tracker.com", false, "good.tracker.com", true},
		{"x.good.tracker.com", false, "good.tracker.com", true},
		{"bad.tracker.com", true, "tracker.com", false},
		{"img.cdn.example", true, "cdn.example", true},
		{"ads.example", true, "ads.example", false},
		{"other.org", false, "", false},
	}
	for _, c := range cases {
		d := p.Decide(c.name)
		if d.Blocked != c.blocked || d.Rule != c.rule || d.Mine != c.mine {
			t.Errorf("%s: %+v, want blocked=%v rule=%q mine=%v", c.name, d, c.blocked, c.rule, c.mine)
		}
	}
}

func TestLoadAdblocklist(t *testing.T) {
	list := `[Adblock Plus 2.0]
! Title: example adblock list
||ads.example^
||partial.example^$third-party
||cdn.example/banner.js^
news.example##.cookie-banner
plain.example
`

	s := NewSet()
	n, err := s.Load(strings.NewReader(list))
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("loaded %d domains, want 2 (ads.example and plain.example)", n)
	}
	for name, want := range map[string]bool{
		"ads.example":     true,
		"cdn.ads.example": true,
		"plain.example":   true,
		"partial.example": false,
		"cdn.example":     false,
		"news.example":    false,
	} {
		if _, got := s.Match(name); got != want {
			t.Errorf("Match(%q) = %v, want %v", name, got, want)
		}
	}
}

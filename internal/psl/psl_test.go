package psl

import "testing"

func TestSplitEmbeddedList(t *testing.T) {
	cases := []struct {
		name                       string
		suffix, registrable, label string
		sub                        string
	}{
		{"example.com", "com", "example.com", "example", ""},
		{"ads.tracker.example.co.uk", "co.uk", "example.co.uk", "example", "ads.tracker"},
		{"co.uk", "co.uk", "", "", ""},
		// Private section: each github.io user is a separate registrant.
		{"blog.alice.github.io", "github.io", "alice.github.io", "alice", "blog"},
		// Not in the list at all: the default rule takes the last label.
		{"adegjkaiggjm.bazar", "bazar", "adegjkaiggjm.bazar", "adegjkaiggjm", ""},
		{"localhost", "localhost", "", "", ""},
		// Wildcard *.ck and exception !www.ck.
		{"shop.example.ck", "example.ck", "shop.example.ck", "shop", ""},
		{"www.ck", "ck", "www.ck", "www", ""},
		// Unicode rule 公司.cn, queried in its punycode form.
		{"shop.xn--55qx5d.cn", "xn--55qx5d.cn", "shop.xn--55qx5d.cn", "shop", ""},
	}
	for _, c := range cases {
		p := Default.Split(c.name)
		if p.Suffix != c.suffix || p.Registrable != c.registrable || p.Label != c.label || p.Sub != c.sub {
			t.Errorf("%s: got %+v", c.name, p)
		}
	}
}

func TestRuleKinds(t *testing.T) {
	l, err := Parse(`
// comment
com
*.wild.test
!keep.wild.test
bücher.test
`)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{ // name -> registrable
		"a.b.com":              "b.com",
		"x.y.wild.test":        "x.y.wild.test", // y.wild.test is a suffix
		"x.keep.wild.test":     "keep.wild.test",
		"a.xn--bcher-kva.test": "a.xn--bcher-kva.test",
		"unknown":              "",
	}
	for name, want := range cases {
		if got := l.Split(name).Registrable; got != want {
			t.Errorf("%s: registrable %q, want %q", name, got, want)
		}
	}
}

func TestEmptyName(t *testing.T) {
	if p := Default.Split(""); p != (Parts{}) {
		t.Errorf("got %+v", p)
	}
}

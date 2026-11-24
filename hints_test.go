package main

import (
	"strings"
	"testing"
)

// hintText joins the hints into one string, to search it.
func hintText(hs []hint) string {
	var b strings.Builder
	for _, h := range hs {
		b.WriteString(h.what + ": " + h.how + "\n")
	}
	return b.String()
}

func TestHintsLinux(t *testing.T) {
	got := hintText(startupHints("linux", "127.0.0.1:5300", 76000, "127.0.0.1:5380"))
	for _, want := range []string{"dig @127.0.0.1 -p 5300 doubleclick.net", "systemd", "watch it live: telescope\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "nothing is blocked") {
		t.Errorf("warned about an empty blocklist that is not empty:\n%s", got)
	}
}

func TestHintsWindowsWrongPort(t *testing.T) {
	got := hintText(startupHints("windows", "127.0.0.1:5300", 0, ""))
	for _, want := range []string{"nothing is blocked", "nslookup -port=5300 doubleclick.net 127.0.0.1", "-listen 127.0.0.1:53"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "dig") || strings.Contains(got, "telescope") {
		t.Errorf("dig or telescope advice on Windows without an API:\n%s", got)
	}
}

func TestHintsEverywhereAndPort53(t *testing.T) {
	got := hintText(startupHints("linux", "0.0.0.0:53", 1, "192.168.1.10:5380"))
	for _, want := range []string{"dig @127.0.0.1 doubleclick.net", "telescope -addr 192.168.1.10:5380"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestHintsBadAddress(t *testing.T) {
	if hs := startupHints("linux", "nonsense", 0, ""); hs != nil {
		t.Errorf("hints for an address that cannot be split: %v", hs)
	}
}

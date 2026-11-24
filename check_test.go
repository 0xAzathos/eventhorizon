package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xAzathos/eventhorizon/internal/lists"
)

func TestCheckPortFree(t *testing.T) {
	// Find a free port by taking one and letting go of it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	if r := checkPort(addr, time.Second); !r.ok {
		t.Fatalf("free port reported as %s", r.detail)
	}
}

func TestCheckPortTakenByNonDNS(t *testing.T) {
	// A UDP socket that never answers: something else holds the port.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	r := checkPort(pc.LocalAddr().String(), 200*time.Millisecond)
	if r.ok || !strings.Contains(r.detail, "another program") {
		t.Fatalf("got ok=%v %q, want a failure naming another program", r.ok, r.detail)
	}
}

func TestCheckUpstreamFailures(t *testing.T) {
	for _, spec := range []string{"not-an-ip", "127.0.0.1:1"} {
		if r := checkUpstream(spec, 200*time.Millisecond); r.ok {
			t.Errorf("upstream %q passed: %s", spec, r.detail)
		}
	}
}

func TestRunCheckExitCode(t *testing.T) {
	var out bytes.Buffer
	cfg := config{listen: "127.0.0.1:0", upstream: "127.0.0.1:1", timeout: 200 * time.Millisecond}
	code := runCheck(&out, cfg, blockedLookup)
	if code != 1 {
		t.Errorf("exit code %d with a dead upstream, want 1", code)
	}
	for _, want := range []string{"FAIL upstream 127.0.0.1:1", "ok   listen 127.0.0.1:0", "FAIL blocklists: none given", "ok   this machine", "2 of 4 checks failed"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
}

// fakeLookup answers example.com with a real address and doubleclick.net
// with probe, or err for both when err is set.
func fakeLookup(probe []netip.Addr, probeErr, err error) lookupFunc {
	return func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if err != nil {
			return nil, err
		}
		if host == "example.com" {
			return []netip.Addr{netip.MustParseAddr("93.184.215.14")}, nil
		}
		return probe, probeErr
	}
}

// blockedLookup acts like a machine whose DNS goes through a blocker.
var blockedLookup = fakeLookup([]netip.Addr{netip.IPv4Unspecified()}, nil, nil)

func TestCheckProtection(t *testing.T) {
	notFound := &net.DNSError{Err: "no such host", IsNotFound: true}
	for _, tc := range []struct {
		name   string
		lookup lookupFunc
		ok     bool
	}{
		{"blocked with 0.0.0.0", blockedLookup, true},
		{"blocked with no such name", fakeLookup(nil, notFound, nil), true},
		{"not blocked", fakeLookup([]netip.Addr{netip.MustParseAddr("142.250.1.1")}, nil, nil), false},
		{"DNS broken, not blocking", fakeLookup(nil, nil, notFound), false},
		{"lookup broken", fakeLookup(nil, nil, errors.New("network is unreachable")), false},
	} {
		if got := checkProtection(tc.lookup, time.Second); got.ok != tc.ok {
			t.Errorf("%s: ok=%v (%s), want %v", tc.name, got.ok, got.detail, tc.ok)
		}
	}
}

func TestCheckList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hosts":
			w.Write([]byte("0.0.0.0 ads.example\n0.0.0.0 tracker.example\n"))
		case "/empty":
			w.Write([]byte("# just a comment\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	loader := &lists.Loader{Client: srv.Client(), CacheDir: t.TempDir()}

	missing := filepath.Join(t.TempDir(), "nope.txt")
	local := filepath.Join(t.TempDir(), "local.txt")
	os.WriteFile(local, []byte("ads.example\n"), 0o600)

	for _, tc := range []struct {
		src, want string
		ok        bool
	}{
		{srv.URL + "/hosts", "2 domains", true},
		{local, "1 domain", true},
		{srv.URL + "/empty", "holds no domains", false},
		{srv.URL + "/gone", "unavailable", false},
		{missing, "unavailable", false},
	} {
		got := checkList(loader, tc.src)
		if got.ok != tc.ok || !strings.Contains(got.detail, tc.want) {
			t.Errorf("%s: ok=%v %q, want ok=%v containing %q", tc.src, got.ok, got.detail, tc.ok, tc.want)
		}
	}
}

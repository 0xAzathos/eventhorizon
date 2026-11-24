package main

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
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
	code := runCheck(&out, "127.0.0.1:0", []string{"127.0.0.1:1"}, 200*time.Millisecond)
	if code != 1 {
		t.Errorf("exit code %d with a dead upstream, want 1", code)
	}
	for _, want := range []string{"FAIL upstream 127.0.0.1:1", "ok   listen 127.0.0.1:0", "1 of 2 checks failed"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
}

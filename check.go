package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/0xAzathos/eventhorizon/internal/upstream"
	"github.com/0xAzathos/eventhorizon/internal/version"
)

// checkResult is the outcome of one -check test.
type checkResult struct {
	ok     bool
	name   string
	detail string
}

// runCheck tests the things that usually stop eventhorizon from working,
// prints one line per test, and returns the exit code: 0 if all passed.
func runCheck(w io.Writer, listen string, upstreams []string, timeout time.Duration) int {
	fmt.Fprintln(w, "eventhorizon", version.String(), "check")
	var results []checkResult
	for _, spec := range upstreams {
		results = append(results, checkUpstream(spec, timeout))
	}
	results = append(results, checkPort(listen, timeout))

	failed := 0
	for _, r := range results {
		mark := "ok  "
		if !r.ok {
			mark = "FAIL"
			failed++
		}
		fmt.Fprintf(w, " %s %s: %s\n", mark, r.name, r.detail)
	}
	if failed > 0 {
		fmt.Fprintf(w, "%d of %d checks failed\n", failed, len(results))
		return 1
	}
	fmt.Fprintln(w, "all checks passed")
	return 0
}

// checkUpstream looks up example.cm through one upstream, the same way
// eventhorizon will: over TLS when the spec says so, certificate checked.
func checkUpstream(spec string, timeout time.Duration) checkResult {
	name := "upstream " + spec
	p, err := upstream.New([]string{spec}, timeout)
	if err != nil {
		return checkResult{false, name, err.Error()}
	}
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*timeout)
	defer cancel()
	start := time.Now()
	if _, err := p.Resolver().LookupNetIP(ctx, "ip4", "example.com"); err != nil {
		return checkResult{false, name, "no answer: " + cause(err)}
	}
	return checkResult{true, name, "answered in " + time.Since(start).Round(time.Millisecond).String()}
}

// checkPort tries to take the listen address on UDP and TCP the way eventhorizon will.
// If it is taken, it asks whoever has it about a name that never exists:
// any DNS answer, even "no such name", means a DNS server holds the port.
// Most likely eventhorizon already running.
func checkPort(listen string, timeout time.Duration) checkResult {
	name := "listen " + listen
	err := tryListen(listen)
	if err == nil {
		return checkResult{true, name, "free"}
	}
	if errors.Is(err, os.ErrPermission) {
		return checkResult{false, name, "not allowed to use this port; ports below 1024 need extra rights on Linux (see the README)"}
	}

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", listen)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, dnsErr := r.LookupNetIP(ctx, "ip4", "eventhorizon-check.invalid.")
	var de *net.DNSError
	if dnsErr == nil || (errors.As(dnsErr, &de) && de.IsNotFound) {
		return checkResult{true, name, "in use by a DNS server, probably eventhorizon already running"}
	}
	return checkResult{false, name, "in use by another program: " + err.Error()}
}

// tryListen takes addr on UDP and TCP and lets go again.
func tryListen(addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	pc.Close()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return ln.Close()
}

// cause trims Go's DNS errors to what went wrong. Their full text names
// the system's own resolver, which has nothing to do with the check.
func cause(err error) string {
	var de *net.DNSError
	if errors.As(err, &de) && de.Err != "" {
		return de.Err
	}
	return err.Error()
}

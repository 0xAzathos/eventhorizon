package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/0xAzathos/eventhorizon/internal/lists"
	"github.com/0xAzathos/eventhorizon/internal/upstream"
	"github.com/0xAzathos/eventhorizon/internal/version"
)

// checkResult is the outcome of one -check test.
type checkResult struct {
	ok     bool
	name   string
	detail string
}

// lookupFunc looks up a name the way this machine normally does.
// net.DefaultResolver.LookupNetIP is one; tests pass fakes.
type lookupFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

func runCheck(w io.Writer, cfg config, lookup lookupFunc) int {
	fmt.Fprintln(w, "eventhorizon", version.String(), "check")
	var results []checkResult
	for _, spec := range splitList(cfg.upstream) {
		results = append(results, checkUpstream(spec, cfg.timeout))
	}
	results = append(results, checkPort(cfg.listen, cfg.timeout))
	results = append(results, checkLists(cfg)...)
	results = append(results, checkProtection(lookup, cfg.timeout))

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

// checkLists downloads or reads every blocklist, one at a time, so each gets its own line.
func checkLists(cfg config) []checkResult {
	if len(cfg.sources) == 0 {
		return []checkResult{{false, "blocklists", "none given, so nothing is blocked; add -blocklist (see the README)"}}
	}
	pool, err := upstream.New(splitList(cfg.upstream), cfg.timeout)
	if err != nil {
		return []checkResult{{false, "blocklists", "not checked: " + err.Error()}}
	}
	defer pool.Close()
	loader := newLoader(pool, cfg.cacheDir)

	var out []checkResult
	for _, src := range cfg.sources {
		out = append(out, checkList(loader, src))
	}
	return out
}

func checkList(loader *lists.Loader, src string) checkResult {
	name := "blocklist " + src
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	set, reports := loader.Build(ctx, []string{src})
	r := reports[0]

	switch {
	case r.Failed():
		return checkResult{false, name, "unavailable: " + r.Err.Error()}
	case r.FromCache:
		return checkResult{false, name, "download failed, an older saved copy would be used: " + r.Err.Error()}
	case set.Len() == 0:
		return checkResult{false, name, "loaded, but it holds no domains; is it a blocklist?"}
	}

	unit := "domains"
	if set.Len() == 1 {
		unit = "domain"
	}
	return checkResult{true, name, fmt.Sprintf("%d %s", set.Len(), unit)}
}

// checkProtection asks this machine's normal resolver about a well known ad domain.
// A blocked answer (0.0.0.0, or no such name) means lookups here pass through a blocker:
// eventhorizon, if it runs and the system points at it. A real address means they do not.
// A control lookup comes first: if example.com fails too, DNS is simply broken, not blocking.
func checkProtection(lookup lookupFunc, timeout time.Duration) checkResult {
	const name, control, probe = "this machine", "example.com", "doubleclick.net"
	ctx, cancel := context.WithTimeout(context.Background(), 2*timeout)
	defer cancel()
	if _, err := lookup(ctx, "ip4", control); err != nil {
		return checkResult{false, name, "cannot look up " + control + " either, so DNS on this machine does not work right now: " + cause(err)}
	}
	addrs, err := lookup(ctx, "ip4", probe)

	var de *net.DNSError
	switch {
	case err == nil && allUnspecified(addrs):
		return checkResult{true, name, probe + " gives 0.0.0.0, so lookups here go through a blocker"}
	case errors.As(err, &de) && de.IsNotFound:
		return checkResult{true, name, probe + " does not resolve, so lookups here go through a blocker"}
	case err != nil:
		return checkResult{false, name, "could not look up " + probe + ": " + cause(err)}
	}
	return checkResult{false, name, fmt.Sprintf("%s resolves to %s, so this machine does not use eventhorizon yet (see the README)", probe, addrs[0])}
}

func allUnspecified(addrs []netip.Addr) bool {
	for _, a := range addrs {
		if !a.IsUnspecified() {
			return false
		}
	}
	return len(addrs) > 0
}

// eventhorizon is a DNS sinkhole: it answers 0.0.0.0 for blocked domains
// and forwards everything else to an upstream resolver.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/0xAzathos/eventhorizon/internal/api"
	"github.com/0xAzathos/eventhorizon/internal/cache"
	"github.com/0xAzathos/eventhorizon/internal/control"
	"github.com/0xAzathos/eventhorizon/internal/detect"
	"github.com/0xAzathos/eventhorizon/internal/events"
	"github.com/0xAzathos/eventhorizon/internal/forward"
	"github.com/0xAzathos/eventhorizon/internal/guard"
	"github.com/0xAzathos/eventhorizon/internal/lists"
	"github.com/0xAzathos/eventhorizon/internal/policy"
	"github.com/0xAzathos/eventhorizon/internal/psl"
	"github.com/0xAzathos/eventhorizon/internal/rules"
	"github.com/0xAzathos/eventhorizon/internal/server"
	"github.com/0xAzathos/eventhorizon/internal/stats"
	"github.com/0xAzathos/eventhorizon/internal/upstream"
	"github.com/0xAzathos/eventhorizon/internal/version"
)

type config struct {
	listen      string
	upstream    string
	forward     string
	sources     []string
	allowlist   string
	cacheDir    string
	refresh     time.Duration
	timeout     time.Duration
	cacheSize   int
	cacheMaxTTL time.Duration
	queryLog    server.QueryLog
	detect      bool
	apiAddr     string
	apiToken    string // path of the token file, empty for none
	clients     string
	rateLimit   float64
	rulesFile   string
}

func main() {
	var cfg config
	var blocklists, queryLog string
	flag.StringVar(&cfg.listen, "listen", "127.0.0.1:5300", "address to listen on (UDP and TCP)")
	flag.StringVar(&cfg.upstream, "upstream", "tls://1.1.1.1#cloudflare-dns.com,tls://9.9.9.9#dns.quad9.net", "comma separated resolvers tried in order: IP[:port] for plain DNS, tls://IP[:port]#name for DNS over TLS")
	flag.StringVar(&cfg.forward, "forward", "", "send your own zones to your router instead of the upstreams, e.g. lan=192.168.1.1,home.arpa=192.168.1.1")
	flag.StringVar(&blocklists, "blocklist", "", "comma separated blocklist files or http(s) URLs")
	flag.StringVar(&cfg.allowlist, "allowlist", "", "allowlist file (plain domains)")
	flag.StringVar(&cfg.cacheDir, "list-cache-dir", defaultListCacheDir(), "where downloaded lists are kept as fallback")
	flag.StringVar(&cfg.rulesFile, "rules", defaultRulesFile(), "file for your own allow and block rules (made from telescope or the API)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.DurationVar(&cfg.refresh, "refresh", 24*time.Hour, "reload lists this often, 0 disables")
	flag.DurationVar(&cfg.timeout, "timeout", 2*time.Second, "timeout for each upstream attempt")
	flag.IntVar(&cfg.cacheSize, "cache-size", 10000, "max cached replies, 0 disables the cache")
	flag.DurationVar(&cfg.cacheMaxTTL, "cache-max-ttl", time.Hour, "never cache a reply longer than this")
	flag.StringVar(&queryLog, "log-queries", "blocked", "which queries to log: all, blocked (includes suspicious) or none")
	flag.BoolVar(&cfg.detect, "detect", true, "watch for DGA malware and DNS tunneling")
	flag.StringVar(&cfg.apiAddr, "api", "127.0.0.1:5380", "local API for the TUI, empty disables it")
	flag.StringVar(&cfg.apiToken, "api-token-file", "", "require the token in this file on every API request, creating it if missing (needed for a non loopback -api)")
	flag.StringVar(&cfg.clients, "allow-clients", "loopback,private", "who may send queries: CIDRs, addresses, or the groups loopback, private, any")
	flag.Float64Var(&cfg.rateLimit, "rate-limit", 200, "queries per second per client (bursts up to 5x), 0 disables")
	flag.Parse()
	if *showVersion {
		fmt.Println("eventhorizon", version.String())
		return
	}

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	log.Info("eventhorizon starting", "version", version.String())

	for _, s := range strings.Split(blocklists, ",") {
		if s = strings.TrimSpace(s); s != "" {
			cfg.sources = append(cfg.sources, s)
			if strings.HasPrefix(strings.ToLower(s), "http://") {
				log.Warn("blocklist is downloaded without encryption; anyone on the path can change it, use https", "url", s)
			}
		}
	}
	var err error
	if cfg.queryLog, err = server.ParseQueryLog(queryLog); err != nil {
		log.Error("bad flag", "err", err)
		os.Exit(2)
	}

	if err := run(log, cfg); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// defaultRulesFile keeps rules with the service's other state, or next to
// where eventhorizon runs during development.
func defaultRulesFile() string {
	if dir := os.Getenv("STATE_DIRECTORY"); dir != "" {
		return filepath.Join(dir, "rules.txt")
	}
	return "eventhorizon-rules.txt"
}

// defaultListCacheDir uses the directory systemd creates for StateDirectory=
// when running as a service, and a local folder otherwise.
func defaultListCacheDir() string {
	if dir := os.Getenv("STATE_DIRECTORY"); dir != "" {
		return dir
	}
	return ".list-cache"
}

func run(log *slog.Logger, cfg config) error {
	var c *cache.Cache
	if cfg.cacheSize > 0 {
		c = cache.New(cfg.cacheSize, cfg.cacheMaxTTL)
	}
	var det *detect.Detector
	if cfg.detect {
		model, err := detect.DefaultModel()
		if err != nil {
			return err
		}
		popular, err := detect.DefaultPopular()
		if err != nil {
			return err
		}
		det = detect.New(detect.DefaultConfig(), model, popular, psl.Default)
		log.Info("threat detection on", "popular_domains_skipped", len(popular))
	}

	hub := events.NewHub()
	st := stats.New(time.Now())

	var upstreams []string
	for _, u := range strings.Split(cfg.upstream, ",") {
		if u = strings.TrimSpace(u); u != "" {
			upstreams = append(upstreams, u)
		}
	}
	pool, err := upstream.New(upstreams, cfg.timeout)
	if err != nil {
		return err
	}
	defer pool.Close()

	fwd, err := forward.Parse(cfg.forward)
	if err != nil {
		return err
	}
	local, closeLocal, err := localRoutes(fwd, cfg.timeout)
	if err != nil {
		return err
	}
	defer closeLocal()
	if fwd.Len() > 0 {
		log.Info("forwarding local zones", "rules", cfg.forward)
	}

	acl, err := guard.ParseACL(cfg.clients)
	if err != nil {
		return err
	}
	if acl.Open() {
		log.Warn("allow-clients includes any: this is an open resolver, only run it behind a firewall")
	}
	var limiter *guard.Limiter
	if cfg.rateLimit > 0 {
		limiter = guard.NewLimiter(cfg.rateLimit, 5*cfg.rateLimit)
	}

	srv := &server.Server{
		ACL:      acl,
		Limit:    limiter,
		Cache:    c,
		Detect:   det,
		Events:   hub,
		Stats:    st,
		Upstream: pool,
		Local:    local,
		Log:      log,
		QueryLog: cfg.queryLog,
	}
	// Downloads resolve names through the upstreams, not the system: when
	// this machine's DNS points at eventhorizon, the system resolver would
	// ask eventhorizon itself, which is not answering yet at startup.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{Timeout: 30 * time.Second, Resolver: pool.Resolver()}).DialContext
	loader := &lists.Loader{
		Client:   &http.Client{Timeout: time.Minute, Transport: transport},
		CacheDir: cfg.cacheDir,
	}

	// Your own rules live in their own file and are applied on top of the
	// lists by the controller, which installs every policy from now on.
	ruleStore, err := rules.Open(cfg.rulesFile)
	if err != nil {
		return err
	}
	ctl := control.New(ruleStore, srv.SetPolicy)
	log.Info("rules loaded", "file", cfg.rulesFile, "rules", len(ruleStore.List()))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// At startup, partial success is fine: better some blocking than none.
	if err := reload(ctx, log, loader, ctl, cfg, false); err != nil {
		return err
	}

	// DNS uses the same port number on UDP and TCP.
	udpConn, err := net.ListenPacket("udp", cfg.listen)
	if err != nil {
		return err
	}
	defer udpConn.Close()
	tcpLn, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		return err
	}
	defer tcpLn.Close()

	errs := make(chan error, 3)
	go func() { errs <- srv.ServeUDP(udpConn) }()
	go func() { errs <- srv.ServeTCP(tcpLn) }()
	log.Info("listening", "addr", cfg.listen, "proto", "udp+tcp", "upstream", cfg.upstream,
		"allow_clients", cfg.clients, "rate_limit", cfg.rateLimit)

	if cfg.apiAddr != "" {
		// The API shows every query and can change rules. The Host check
		// only stops web pages; anything else that can connect may send
		// any Host. So a network address needs a real secret.
		if !api.IsLoopback(cfg.apiAddr) && cfg.apiToken == "" {
			return fmt.Errorf("-api %s is reachable from the network: set -api-token-file too", cfg.apiAddr)
		}
		handler, err := api.New(cfg.apiAddr, st, hub)
		if err != nil {
			return err
		}
		if cfg.apiToken != "" {
			token, created, err := api.LoadOrCreateToken(cfg.apiToken)
			if err != nil {
				return fmt.Errorf("api token: %w", err)
			}
			handler.Token = token
			if created {
				log.Info("created API token; give it to telescope with -token-file", "file", cfg.apiToken)
			}
		}
		handler.Sizes = func() (int, int) { return srv.BlocklistSize(), c.Len() }
		handler.Upstreams = pool.Status
		handler.Control = ctl
		apiLn, err := net.Listen("tcp", cfg.apiAddr)
		if err != nil {
			return err
		}
		apiSrv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
		defer apiSrv.Close()
		go func() {
			if err := apiSrv.Serve(apiLn); !errors.Is(err, http.ErrServerClosed) {
				errs <- err
			}
		}()
		log.Info("api listening", "addr", cfg.apiAddr, "token", handler.Token != "")
	}

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

	var tick <-chan time.Time
	if cfg.refresh > 0 {
		t := time.NewTicker(cfg.refresh)
		defer t.Stop()
		tick = t.C
	}

	for {
		select {
		case <-ctx.Done():
			log.Info("shut down")
			return nil
		case err := <-errs:
			return err
		case <-hup:
			log.Info("reload requested")
		case <-tick:
			log.Info("scheduled reload")
		case reply := <-ctl.Requests():
			// From the API. Handled here, so it can never overlap with a
			// scheduled reload or one from SIGHUP.
			log.Info("reload requested through the API")
			err := reload(ctx, log, loader, ctl, cfg, true)
			if err != nil {
				log.Warn("reload failed, keeping previous lists", "err", err)
			}
			reply <- err
			continue
		}
		// After startup, be strict: if any list is unavailable, keep the
		// policy we already have rather than silently block less.
		if err := reload(ctx, log, loader, ctl, cfg, true); err != nil {
			log.Warn("reload failed, keeping previous lists", "err", err)
		}
	}
}

// reload builds a complete new policy and only then swaps it in.
func reload(ctx context.Context, log *slog.Logger, loader *lists.Loader, ctl *control.Controller, cfg config, strict bool) error {
	block, reports := loader.Build(ctx, cfg.sources)

	failed := 0
	for _, r := range reports {
		switch {
		case r.Failed():
			failed++
			log.Warn("blocklist unavailable", "source", r.Source, "err", r.Err)
		case r.FromCache:
			log.Warn("blocklist download failed, using saved copy", "source", r.Source, "err", r.Err)
		case r.Err != nil:
			log.Warn("blocklist loaded with a problem", "source", r.Source, "err", r.Err)
		}
		if !r.Failed() {
			log.Info("loaded blocklist", "source", r.Source, "new", r.Added)
		}
	}
	if failed > 0 && (strict || failed == len(reports)) {
		return fmt.Errorf("%d of %d blocklists unavailable", failed, len(reports))
	}

	var allow *policy.Set
	if cfg.allowlist != "" {
		allow = policy.NewSet()
		f, err := os.Open(cfg.allowlist)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := allow.Load(f); err != nil {
			return errors.Join(fmt.Errorf("allowlist %s", cfg.allowlist), err)
		}
	}

	ctl.SetLists(block, allow)
	log.Info("lists active", "blocked_domains", block.Len(), "allowed_domains", allow.Len())
	return nil
}

// localRoutes opens one pool for each server in the -forward rules and
// returns the server's Local function, plus a function that cloese them.
func localRoutes(fwd *forward.Table, timeout time.Duration) (func(string) *upstream.Pool, func(), error) {
	pools := map[netip.AddrPort]*upstream.Pool{}
	closeAll := func() {
		for _, p := range pools {
			p.Close()
		}
	}
	for _, ap := range fwd.Servers() {
		p, err := upstream.New([]string{ap.String()}, timeout)
		if err != nil {
			closeAll()
			return nil, nil, err
		}
		pools[ap] = p
	}
	route := func(name string) *upstream.Pool {
		ap, ok := fwd.Lookup(name)
		if !ok {
			return nil
		}
		return pools[ap]
	}
	return route, closeAll, nil
}

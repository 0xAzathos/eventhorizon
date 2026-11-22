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
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"eventhorizon/internal/cache"
	"eventhorizon/internal/detect"
	"eventhorizon/internal/lists"
	"eventhorizon/internal/policy"
	"eventhorizon/internal/psl"
	"eventhorizon/internal/server"
)

type config struct {
	listen      string
	upstream    string
	sources     []string
	allowlist   string
	cacheDir    string
	refresh     time.Duration
	timeout     time.Duration
	cacheSize   int
	cacheMaxTTL time.Duration
	queryLog    server.QueryLog
	detect      bool
}

func main() {
	var cfg config
	var blocklists, queryLog string
	flag.StringVar(&cfg.listen, "listen", "127.0.0.1:5300", "address to listen on (UDP and TCP)")
	flag.StringVar(&cfg.upstream, "upstream", "1.1.1.1:53", "upstream resolver")
	flag.StringVar(&blocklists, "blocklist", "", "comma separated blocklist files or http(s) URLs")
	flag.StringVar(&cfg.allowlist, "allowlist", "", "allowlist file (plain domains)")
	flag.StringVar(&cfg.cacheDir, "list-cache-dir", defaultListCacheDir(), "where downloaded lists are kept as fallback")
	flag.DurationVar(&cfg.refresh, "refresh", 24*time.Hour, "reload lists this often, 0 disables")
	flag.DurationVar(&cfg.timeout, "timeout", 2*time.Second, "upstream query timeout")
	flag.IntVar(&cfg.cacheSize, "cache-size", 10000, "max cached replies, 0 disables the cache")
	flag.DurationVar(&cfg.cacheMaxTTL, "cache-max-ttl", time.Hour, "never cache a reply longer than this")
	flag.StringVar(&queryLog, "log-queries", "all", "which queries to log: all, blocked (includes suspicious) or none")
	flag.BoolVar(&cfg.detect, "detect", true, "watch for DGA malware and DNS tunneling")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	for _, s := range strings.Split(blocklists, ",") {
		if s = strings.TrimSpace(s); s != "" {
			cfg.sources = append(cfg.sources, s)
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

	srv := &server.Server{
		Cache:    c,
		Detect:   det,
		Upstream: cfg.upstream,
		Timeout:  cfg.timeout,
		Log:      log,
		QueryLog: cfg.queryLog,
	}
	loader := &lists.Loader{
		Client:   &http.Client{Timeout: time.Minute},
		CacheDir: cfg.cacheDir,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// At startup, partial success is fine: better some blocking than none.
	if err := reload(ctx, log, loader, srv, cfg, false); err != nil {
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

	errs := make(chan error, 2)
	go func() { errs <- srv.ServeUDP(udpConn) }()
	go func() { errs <- srv.ServeTCP(tcpLn) }()
	log.Info("listening", "addr", cfg.listen, "proto", "udp+tcp", "upstream", cfg.upstream)

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
		}
		// After startup, be strict: if any list is unavailable, keep the
		// policy we already have rather than silently block less.
		if err := reload(ctx, log, loader, srv, cfg, true); err != nil {
			log.Warn("reload failed, keeping previous lists", "err", err)
		}
	}
}

// reload builds a complete new policy and only then swaps it in.
func reload(ctx context.Context, log *slog.Logger, loader *lists.Loader, srv *server.Server, cfg config, strict bool) error {
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

	srv.SetPolicy(&policy.Policy{Block: block, Allow: allow})
	log.Info("lists active", "blocked_domains", block.Len(), "allowed_domains", allow.Len())
	return nil
}

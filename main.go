// sinkhole is a DNS server that answers 0.0.0.0 for blocked domains and
// forwards everything else to an upstream resolver.
package main
 
import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
 
	"eventhorizon/internal/cache"
	"eventhorizon/internal/policy"
	"eventhorizon/internal/server"
)
 
func main() {
	listen := flag.String("listen", "127.0.0.1:5300", "address to listen on (UDP and TCP)")
	upstream := flag.String("upstream", "1.1.1.1:53", "upstream resolver")
	blocklists := flag.String("blocklist", "", "comma separated blocklist files (hosts or plain domains)")
	allowlist := flag.String("allowlist", "", "allowlist file (plain domains)")
	timeout := flag.Duration("timeout", 2*time.Second, "upstream query timeout")
	cacheSize := flag.Int("cache-size", 10000, "max cached replies, 0 disables the cache")
	cacheMaxTTL := flag.Duration("cache-max-ttl", time.Hour, "never cache a reply longer than this")
	flag.Parse()
 
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
 
	var c *cache.Cache
	if *cacheSize > 0 {
		c = cache.New(*cacheSize, *cacheMaxTTL)
	}
 
	if err := run(log, c, *listen, *upstream, *blocklists, *allowlist, *timeout); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}
 
func run(log *slog.Logger, c *cache.Cache, listen, upstream, blocklists, allowlist string, timeout time.Duration) error {
	block := policy.NewSet()
	for _, path := range strings.Split(blocklists, ",") {
		if path = strings.TrimSpace(path); path == "" {
			continue
		}
		n, err := loadFile(block, path)
		if err != nil {
			return err
		}
		log.Info("loaded blocklist", "file", path, "new", n, "total", block.Len())
	}
 
	var allow *policy.Set
	if allowlist != "" {
		allow = policy.NewSet()
		n, err := loadFile(allow, allowlist)
		if err != nil {
			return err
		}
		log.Info("loaded allowlist", "file", allowlist, "domains", n)
	}
 
	// DNS uses the same port number on UDP and TCP.
	udpConn, err := net.ListenPacket("udp", listen)
	if err != nil {
		return err
	}
	tcpLn, err := net.Listen("tcp", listen)
	if err != nil {
		udpConn.Close()
		return err
	}
 
	srv := &server.Server{
		Policy:   &policy.Policy{Block: block, Allow: allow},
		Cache:    c,
		Upstream: upstream,
		Timeout:  timeout,
		Log:      log,
	}
 
	errs := make(chan error, 2)
	go func() { errs <- srv.ServeUDP(udpConn) }()
	go func() { errs <- srv.ServeTCP(tcpLn) }()
	log.Info("listening", "addr", listen, "proto", "udp+tcp", "upstream", upstream)
 
	// Stop on Ctrl+C / SIGTERM, or if either listener dies.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
 
	select {
	case <-ctx.Done():
		err = nil
	case err = <-errs:
	}
	udpConn.Close()
	tcpLn.Close()
	log.Info("shut down")
	return err
}
 
func loadFile(s *policy.Set, path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n, err := s.Load(f)
	if err != nil {
		return n, fmt.Errorf("%s: %w", path, err)
	}
	return n, nil
}
 
// Package server answers DNS over UDP and TCP: parse, decide, then either
// answer from the sinkhole or forward the raw query upstream.
//
// The core (respond, forward) does not care about the transport. udp.go and
// tcp.go only move bytes in and out.
package server

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0xAzathos/eventhorizon/internal/cache"
	"github.com/0xAzathos/eventhorizon/internal/detect"
	"github.com/0xAzathos/eventhorizon/internal/dnsmsg"
	"github.com/0xAzathos/eventhorizon/internal/events"
	"github.com/0xAzathos/eventhorizon/internal/guard"
	"github.com/0xAzathos/eventhorizon/internal/policy"
	"github.com/0xAzathos/eventhorizon/internal/psl"
	"github.com/0xAzathos/eventhorizon/internal/stats"
	"github.com/0xAzathos/eventhorizon/internal/upstream"
)

// QueryLog chooses which queries get a log line.
type QueryLog int

const (
	LogAll     QueryLog = iota
	LogBlocked          // blocked and suspicious queries only
	LogNone
)

func ParseQueryLog(s string) (QueryLog, error) {
	switch s {
	case "all":
		return LogAll, nil
	case "blocked":
		return LogBlocked, nil
	case "none":
		return LogNone, nil
	}
	return 0, fmt.Errorf("unknown query log mode %q (want all, blocked or none)", s)
}

type Server struct {
	Cache    *cache.Cache                     // nil disables caching
	Detect   *detect.Detector                 // nil disables threat detection
	Events   *events.Hub                      // nil: no live viewers
	Stats    *stats.Stats                     // nil: no dashboard statistics
	Upstream *upstream.Pool                   // resolvers with failover, UDP and TCP
	Local    func(name string) *upstream.Pool // your own zones (-forward); nil or a nil result means Upstream
	ACL      *guard.ACL                       // nil: every client may ask
	Limit    *guard.Limiter                   // nil: no rate limit
	Log      *slog.Logger
	QueryLog QueryLog

	// The policy is swapped as a whole when lists are reloaded. Queries
	// running at that moment finish with the old one; the next query sees
	// the new one. No locks, and no query ever sees a half built policy.
	policy atomic.Pointer[policy.Policy]

	reportsOnce sync.Once
	reports     *guard.Reporter
}

// SetPolicy installs p for all queries from now on.
func (s *Server) SetPolicy(p *policy.Policy) {
	s.policy.Store(p)
}

// BlocklistSize reports how many domains the active policy blocks.
func (s *Server) BlocklistSize() int {
	if p := s.policy.Load(); p != nil {
		return p.Block.Len()
	}
	return 0
}

// pickPool returns the pool that should answer name: the local server
// from -forward when one of its zones covers the name, else the upstreams.
func (s *Server) pickPool(name string) *upstream.Pool {
	if s.Local != nil {
		if p := s.Local(name); p != nil {
			return p
		}
	}
	return s.Upstream
}

// respond turns one query into one reply. proto is "udp" or "tcp" and is
// also the transport used upstream: a client that retried over TCP because
// of truncation needs a TCP answer from upstream too. Returns nil when no
// reply should be sent.
func (s *Server) respond(msg []byte, client net.Addr, proto string) []byte {
	start := time.Now()

	q, err := dnsmsg.Parse(msg)
	if err != nil {
		s.Log.Warn("bad query", "proto", proto, "client", client.String(), "err", err)
		return dnsmsg.ErrorResponse(msg, dnsmsg.RcodeFormErr)
	}

	pol := s.policy.Load()
	decision := pol.Decide(q.Name)
	var sig detect.Signals
	if !decision.Blocked {
		sig = s.Detect.Inspect(q.Name)
	}

	// Over UDP the reply must fit the client's buffer; TCP has no such limit.
	maxSize := 65535
	if proto == "udp" {
		maxSize = q.UDPSize
	}

	var resp []byte
	var action string
	if decision.Blocked {
		resp, action = q.Blocked(), "blocked"
	} else if cached, ok := s.Cache.Get(q, time.Now(), maxSize); ok {
		resp, action = cached, "cached"
	} else {
		var res upstream.Result
		res, err = s.pickPool(q.Name).Exchange(proto, msg, q.ID)
		resp = res.Resp
		if res.Attempts > 1 && err == nil {
			s.Log.Debug("answered after failover", "name", q.Name, "server", res.Server, "attempts", res.Attempts)
		}
		if err != nil {
			s.Log.Warn("upstream failed", "proto", proto, "name", q.Name, "err", err)
			resp, action = dnsmsg.ErrorResponse(msg, dnsmsg.RcodeServFail), "servfail"
		} else {
			s.Cache.Put(q, resp, time.Now())
			action = "allowed"
		}
	}

	// CNAME cloaking: a first party looking name can be an alias for a
	// tracker. Check every name the answer points to. This also runs on
	// cache hits, so a list reload applies to answers cached before it.
	// Names on the allowlist (a matching rule that did not block) are
	// left alone.
	var via string
	if (action == "allowed" || action == "cached") && decision.Rule == "" {
		if targets, err := dnsmsg.CNAMETargets(resp); err == nil {
			for _, target := range targets {
				if d := pol.Decide(target); d.Blocked {
					resp, action, decision, via = q.Blocked(), "blocked", d, target
					break
				}
			}
		}
	}

	// Over TCP or TLS the upstream sends the full answer however big. A
	// UDP client only takes what it advertised; anything larger becomes
	// "truncated, retry over TCP". (Cached answers are already size checked.)
	if action == "allowed" && len(resp) > maxSize {
		resp = dnsmsg.Truncate(resp)
	}

	// Detection needs the outcome: a random looking name that does not
	// exist (NXDOMAIN) is what DGA malware produces.
	if sig.Any() && (action == "allowed" || action == "cached") && len(resp) >= 4 {
		rcode := int(resp[3] & 0x0F)
		for _, a := range s.Detect.Observe(clientIP(client), q.Name, sig, rcode) {
			attrs := []any{"kind", a.Kind, "client", a.Client}
			if a.Domain != "" {
				attrs = append(attrs, "domain", a.Domain)
			}
			attrs = append(attrs, "count", a.Count, "examples", strings.Join(a.Examples, ","))
			s.Log.Warn("threat detected", attrs...)

			s.Stats.RecordAlert()
			s.Events.Publish(events.Event{
				Time: time.Now(), Kind: "alert", Alert: a.Kind, Client: a.Client,
				Domain: a.Domain, Count: a.Count, Examples: a.Examples,
			})
		}
	}

	s.record(proto, client, q, action, decision.Rule, via, sig, start)

	if s.QueryLog == LogAll || (s.QueryLog == LogBlocked && (decision.Blocked || sig.Any())) {
		s.logQuery(proto, client, q, action, decision.Rule, via, sig, start)
	}
	return resp
}

func (s *Server) logQuery(proto string, client net.Addr, q *dnsmsg.Query, action, rule, via string, sig detect.Signals, start time.Time) {
	attrs := []any{
		"proto", proto,
		"client", client.String(),
		"name", q.Name,
		"type", dnsmsg.TypeName(q.Type),
		"action", action,
		"rule", rule,
		"took", time.Since(start).Round(time.Microsecond),
	}
	if via != "" {
		attrs = append(attrs, "via", via) // blocked through this CNAME target
	}
	if label := sig.Label(); label != "" {
		attrs = append(attrs, "suspicious", label)
	}
	s.Log.Info("query", attrs...)
}

// record feeds the dashboard: totals and top lists, plus the live stream.
func (s *Server) record(proto string, client net.Addr, q *dnsmsg.Query, action, rule, via string, sig detect.Signals, start time.Time) {
	if s.Stats == nil && s.Events == nil {
		return
	}
	now := time.Now()
	ip := clientIP(client)

	registrable := sig.Registrable
	if registrable == "" && s.Stats != nil {
		registrable = psl.Default.Split(q.Name).Registrable
	}
	s.Stats.Record(now, action, ip, q.Name, registrable, sig.Any())

	s.Events.Publish(events.Event{
		Time: now, Kind: "query", Proto: proto, Client: ip, Name: q.Name,
		Type: dnsmsg.TypeName(q.Type), Action: action, Rule: rule, Via: via,
		Suspicious: sig.Label(), TookMicros: now.Sub(start).Microseconds(),
	})
}

// clientIP drops the port: detection counts per device, and a device
// uses a new source port for almost every query.
func clientIP(a net.Addr) string {
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}

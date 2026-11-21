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
	"time"
 
	"eventhorizon/internal/cache"
	"eventhorizon/internal/dnsmsg"
	"eventhorizon/internal/policy"
)
 
type Server struct {
	Policy   *policy.Policy
	Cache    *cache.Cache  // nil disables caching
	Upstream string        // "1.1.1.1:53", used for both UDP and TCP
	Timeout  time.Duration // per upstream query
	Log      *slog.Logger
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
 
	decision := s.Policy.Decide(q.Name)
 
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
		resp, err = s.forward(proto, msg, q.ID)
		if err != nil {
			s.Log.Warn("upstream failed", "proto", proto, "name", q.Name, "err", err)
			resp, action = dnsmsg.ErrorResponse(msg, dnsmsg.RcodeServFail), "servfail"
		} else {
			s.Cache.Put(q, resp, time.Now())
			action = "allowed"
		}
	}
 
	s.Log.Info("query",
		"proto", proto,
		"client", client.String(),
		"name", q.Name,
		"type", dnsmsg.TypeName(q.Type),
		"action", action,
		"rule", decision.Rule,
		"took", time.Since(start).Round(time.Microsecond),
	)
	return resp
}
 
// forward sends the original bytes upstream untouched (so EDNS options and
// everything else survive) and returns the reply whose ID matches.
func (s *Server) forward(proto string, msg []byte, id uint16) ([]byte, error) {
	c, err := net.DialTimeout(proto, s.Upstream, s.Timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
 
	if err := c.SetDeadline(time.Now().Add(s.Timeout)); err != nil {
		return nil, err
	}
 
	if proto == "tcp" {
		if err := writeFramed(c, msg); err != nil {
			return nil, err
		}
		resp, err := readFramed(c)
		if err != nil {
			return nil, err
		}
		if got, ok := dnsmsg.ResponseID(resp); !ok || got != id {
			return nil, fmt.Errorf("upstream reply has wrong id")
		}
		return resp, nil
	}
 
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		// Ignore stray packets; a reply must carry our query's ID.
		if got, ok := dnsmsg.ResponseID(buf[:n]); ok && got == id {
			return buf[:n], nil
		}
	}
}
 
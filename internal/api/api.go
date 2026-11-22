// Package api serves eventhorizon's live data to local viewers like the
// TUI:
//
//	GET /api/stats   JSON snapshot: totals, per second history, top lists
//	GET /api/events  newline delimited JSON: recent events, then live ones
//
// The data is effectively the machine's browsing history, so the API only
// answers requests addressed to a loopback name. That stops DNS rebinding:
// a web page that points its own domain at 127.0.0.1 still sends its own
// domain in the Host header, and gets refused.
package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"time"

	"eventhorizon/internal/events"
	"eventhorizon/internal/stats"
)

type Server struct {
	Stats  *stats.Stats
	Hub    *events.Hub
	Sizes  func() (blocklist, cache int) // optional, filled into snapshots
	TopN   int
	now    func() time.Time
	mux    *http.ServeMux
	allows map[string]bool
}

// New builds the handler for an API listening on addr ("127.0.0.1:5380").
func New(addr string, st *stats.Stats, hub *events.Hub) (*Server, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	s := &Server{
		Stats: st,
		Hub:   hub,
		TopN:  10,
		now:   time.Now,
		mux:   http.NewServeMux(),
		allows: map[string]bool{
			net.JoinHostPort("127.0.0.1", port): true,
			net.JoinHostPort("::1", port):       true,
			net.JoinHostPort("localhost", port): true,
		},
	}
	s.mux.HandleFunc("GET /api/stats", s.stats)
	s.mux.HandleFunc("GET /api/events", s.events)
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.allows[r.Host] {
		http.Error(w, "forbidden host", http.StatusForbidden)
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	n := s.TopN
	if v, err := strconv.Atoi(r.URL.Query().Get("top")); err == nil && v > 0 && v <= 100 {
		n = v
	}
	snap := s.Stats.Snapshot(s.now(), n)
	if s.Sizes != nil {
		snap.Blocklist, snap.CacheSize = s.Sizes()
	}
	snap.DroppedLive = s.Hub.Dropped()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(snap)
}

// events streams one JSON object per line until the client goes away.
// A heartbeat line ("{}") every few seconds lets a viewer notice a dead
// connection even when there is no traffic.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")

	ch, cancel := s.Hub.Subscribe()
	defer cancel()

	enc := json.NewEncoder(w)
	heartbeat := time.NewTicker(5 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case e, open := <-ch:
			if !open {
				return
			}
			if err := enc.Encode(e); err != nil {
				return
			}
			// Send everything already queued, then flush once.
			for drained := false; !drained; {
				select {
				case e, open := <-ch:
					if !open {
						return
					}
					if err := enc.Encode(e); err != nil {
						return
					}
				default:
					drained = true
				}
			}
			flusher.Flush()
		case <-heartbeat.C:
			if _, err := w.Write([]byte("{}\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// IsLoopback reports whether addr's host is a loopback address, so the
// caller can warn when the API is exposed to the network.
func IsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Package api serves eventhorizon's live data to local viewers like the
// TUI:
//
//	GET /api/stats   JSON snapshot: totals, per second history, top lists
//	GET /api/events  newline delimited JSON: recent events, then live ones
//
//	GET    /api/rules   the user's own allow and block rules
//	POST   /api/rules   {"domain": "...", "action": "allow"|"block"}
//	DELETE /api/rules?domain=...
//	POST   /api/reload  download the blocklists again
//
// The data is effectively the machine's browsing history, so the API only
// answers requests addressed to a loopback name. That stops DNS rebinding:
// a web page that points its own domain at 127.0.0.1 still sends its own
// domain in the Host header, and gets refused.
//
// Changes need one more defense. Browsers let any web page send a simple
// POST to 127.0.0.1, with the right Host header, without asking (they only
// hide the reply). So every change request must carry the ChangeHeader.
// A browser will not add a custom header to a cross site request without
// first asking permission (a CORS preflight), which this API never grants.
package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"time"

	"eventhorizon/internal/events"
	"eventhorizon/internal/rules"
	"eventhorizon/internal/stats"
	"eventhorizon/internal/upstream"
)

// ChangeHeader must be present, with any value, on every request that
// changes something.
const ChangeHeader = "X-Eventhorizon-Change"

// Control is what the change endpoints act on (see internal/control).
type Control interface {
	Rules() []rules.Rule
	SetRule(domain, action string) (rules.Rule, error)
	RemoveRule(domain string) (bool, error)
	Reload(ctx context.Context) error
}

type Server struct {
	Control   Control // nil: change endpoints answer 501
	Stats     *stats.Stats
	Hub       *events.Hub
	Sizes     func() (blocklist, cache int) // optional, filled into snapshots
	Upstreams func() []upstream.Status      // optional, filled into snapshots
	TopN      int
	now       func() time.Time
	mux       *http.ServeMux
	allows    map[string]bool
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
	s.mux.HandleFunc("GET /api/rules", s.listRules)
	s.mux.HandleFunc("POST /api/rules", s.setRule)
	s.mux.HandleFunc("DELETE /api/rules", s.removeRule)
	s.mux.HandleFunc("POST /api/reload", s.reload)
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !s.allows[r.Host] {
		http.Error(w, "forbidden host", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get(ChangeHeader) == "" {
		http.Error(w, "missing "+ChangeHeader+" header", http.StatusForbidden)
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
	if s.Upstreams != nil {
		snap.Upstreams = s.Upstreams()
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

type errorBody struct {
	Error string `json:"error"`
}

func (s *Server) control(w http.ResponseWriter) bool {
	if s.Control == nil {
		writeJSON(w, http.StatusNotImplemented, errorBody{"rule changes are not enabled"})
		return false
	}
	return true
}

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	if s.control(w) {
		writeJSON(w, http.StatusOK, s.Control.Rules())
	}
}

func (s *Server) setRule(w http.ResponseWriter, r *http.Request) {
	if !s.control(w) {
		return
	}
	var req rules.Rule
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{"body must be JSON: {\"domain\": ..., \"action\": ...}"})
		return
	}
	rule, err := s.Control.SetRule(req.Domain, req.Action)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) removeRule(w http.ResponseWriter, r *http.Request) {
	if !s.control(w) {
		return
	}
	ok, err := s.Control.RemoveRule(r.URL.Query().Get("domain"))
	switch {
	case err != nil:
		writeJSON(w, http.StatusBadRequest, errorBody{err.Error()})
	case !ok:
		writeJSON(w, http.StatusNotFound, errorBody{"no rule for that domain"})
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) reload(w http.ResponseWriter, r *http.Request) {
	if !s.control(w) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	if err := s.Control.Reload(ctx); err != nil {
		writeJSON(w, http.StatusBadGateway, errorBody{err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
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

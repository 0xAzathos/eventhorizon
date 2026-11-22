package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"eventhorizon/internal/events"
	"eventhorizon/internal/stats"
)

func newAPI(t *testing.T) (*Server, *stats.Stats, *events.Hub) {
	t.Helper()
	st := stats.New(time.Now())
	hub := events.NewHub()
	s, err := New("127.0.0.1:5380", st, hub)
	if err != nil {
		t.Fatal(err)
	}
	s.Sizes = func() (int, int) { return 76105, 42 }
	return s, st, hub
}

func get(s *Server, host, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestStatsJSON(t *testing.T) {
	s, st, _ := newAPI(t)
	st.Record(time.Now(), "blocked", "127.0.0.1", "ads.tracker.com", "tracker.com", false)

	w := get(s, "127.0.0.1:5380", "/api/stats")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var snap stats.Snapshot
	if err := json.Unmarshal(w.Body.Bytes(), &snap); err != nil {
		t.Fatal(err)
	}
	if snap.Totals.Blocked != 1 || snap.Blocklist != 76105 || snap.CacheSize != 42 {
		t.Errorf("snapshot = %+v", snap)
	}
	if len(snap.TopBlocked) != 1 || snap.TopBlocked[0].Key != "ads.tracker.com" {
		t.Errorf("top blocked = %+v", snap.TopBlocked)
	}
}

func TestRejectsForeignHost(t *testing.T) {
	s, _, _ := newAPI(t)
	for _, host := range []string{"evil.example:5380", "127.0.0.1:9999", "192.168.1.10:5380"} {
		if w := get(s, host, "/api/stats"); w.Code != http.StatusForbidden {
			t.Errorf("host %s: status %d, want 403", host, w.Code)
		}
	}
	for _, host := range []string{"localhost:5380", "[::1]:5380"} {
		if w := get(s, host, "/api/stats"); w.Code != http.StatusOK {
			t.Errorf("host %s: status %d, want 200", host, w.Code)
		}
	}
}

func TestOnlyGET(t *testing.T) {
	s, _, _ := newAPI(t)
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:5380/api/stats", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status %d", w.Code)
	}
}

func TestEventStream(t *testing.T) {
	s, _, hub := newAPI(t)
	hub.Publish(events.Event{Kind: "query", Name: "before.example"}) // backlog

	srv := httptest.NewServer(s)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/events", nil)
	req.Host = "127.0.0.1:5380"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("content type %q", ct)
	}

	lines := bufio.NewScanner(resp.Body)
	next := func() events.Event {
		t.Helper()
		if !lines.Scan() {
			t.Fatalf("stream ended: %v", lines.Err())
		}
		var e events.Event
		if err := json.Unmarshal(lines.Bytes(), &e); err != nil {
			t.Fatalf("bad line %q: %v", lines.Text(), err)
		}
		return e
	}

	if e := next(); e.Name != "before.example" {
		t.Errorf("first event %+v, want the backlog", e)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		hub.Publish(events.Event{Kind: "alert", Alert: "dga", Client: "10.0.0.5", Count: 5})
	}()
	if e := next(); e.Kind != "alert" || e.Alert != "dga" || e.Count != 5 {
		t.Errorf("live event %+v", e)
	}
}

func TestIsLoopback(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:5380":   true,
		"[::1]:5380":       true,
		"localhost:5380":   true,
		"0.0.0.0:5380":     false,
		"192.168.1.2:5380": false,
		"garbage":          false,
	}
	for addr, want := range cases {
		if got := IsLoopback(addr); got != want {
			t.Errorf("%s: %v", addr, got)
		}
	}
}

func TestEventJSONOmitsEmptyFields(t *testing.T) {
	b, _ := json.Marshal(events.Event{Kind: "query", Name: "a.example", Action: "allowed"})
	if strings.Contains(string(b), "alert") || strings.Contains(string(b), "examples") {
		t.Errorf("empty alert fields serialized: %s", b)
	}
}

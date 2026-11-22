package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"eventhorizon/internal/events"
	"eventhorizon/internal/rules"
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
	r.Header.Set(ChangeHeader, "1")
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

// fakeControl stands in for internal/control.
type fakeControl struct {
	rules     map[string]string
	reloadErr error
	reloads   int
}

func (f *fakeControl) Rules() []rules.Rule {
	var out []rules.Rule
	for d, a := range f.rules {
		out = append(out, rules.Rule{Domain: d, Action: a})
	}
	return out
}

func (f *fakeControl) SetRule(domain, action string) (rules.Rule, error) {
	if action != rules.Allow && action != rules.Block {
		return rules.Rule{}, errors.New("bad action")
	}
	f.rules[domain] = action
	return rules.Rule{Domain: domain, Action: action}, nil
}

func (f *fakeControl) RemoveRule(domain string) (bool, error) {
	_, ok := f.rules[domain]
	delete(f.rules, domain)
	return ok, nil
}

func (f *fakeControl) Reload(context.Context) error {
	f.reloads++
	return f.reloadErr
}

func change(s *Server, method, path, body string, withHeader bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1:5380"+path, strings.NewReader(body))
	if withHeader {
		r.Header.Set(ChangeHeader, "1")
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestChangesNeedTheHeader(t *testing.T) {
	s, _, _ := newAPI(t)
	fc := &fakeControl{rules: map[string]string{}}
	s.Control = fc

	// What a malicious web page can send: a simple cross site POST.
	w := change(s, http.MethodPost, "/api/rules", `{"domain":"tracker.example","action":"allow"}`, false)
	if w.Code != http.StatusForbidden || len(fc.rules) != 0 {
		t.Errorf("status %d, rules %v: change without the header went through", w.Code, fc.rules)
	}
	if w := change(s, http.MethodPost, "/api/reload", "", false); w.Code != http.StatusForbidden || fc.reloads != 0 {
		t.Errorf("reload without the header: status %d", w.Code)
	}
}

func TestRuleEndpoints(t *testing.T) {
	s, _, _ := newAPI(t)
	fc := &fakeControl{rules: map[string]string{}}
	s.Control = fc

	w := change(s, http.MethodPost, "/api/rules", `{"domain":"github.com","action":"allow"}`, true)
	if w.Code != http.StatusOK || fc.rules["github.com"] != "allow" {
		t.Fatalf("set: status %d body %s", w.Code, w.Body)
	}

	w = get(s, "127.0.0.1:5380", "/api/rules")
	var list []rules.Rule
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list) != 1 || list[0].Domain != "github.com" {
		t.Errorf("list: %s %v", w.Body, err)
	}

	if w := change(s, http.MethodPost, "/api/rules", `{"domain":"x.example","action":"maybe"}`, true); w.Code != http.StatusBadRequest {
		t.Errorf("bad action: status %d", w.Code)
	}
	if w := change(s, http.MethodPost, "/api/rules", `not json`, true); w.Code != http.StatusBadRequest {
		t.Errorf("bad body: status %d", w.Code)
	}

	if w := change(s, http.MethodDelete, "/api/rules?domain=github.com", "", true); w.Code != http.StatusNoContent || len(fc.rules) != 0 {
		t.Errorf("delete: status %d", w.Code)
	}
	if w := change(s, http.MethodDelete, "/api/rules?domain=github.com", "", true); w.Code != http.StatusNotFound {
		t.Errorf("delete missing: status %d", w.Code)
	}
}

func TestReloadEndpoint(t *testing.T) {
	s, _, _ := newAPI(t)
	fc := &fakeControl{rules: map[string]string{}}
	s.Control = fc

	if w := change(s, http.MethodPost, "/api/reload", "", true); w.Code != http.StatusNoContent || fc.reloads != 1 {
		t.Errorf("reload: status %d, reloads %d", w.Code, fc.reloads)
	}
	fc.reloadErr = errors.New("1 of 1 blocklists unavailable")
	w := change(s, http.MethodPost, "/api/reload", "", true)
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "unavailable") {
		t.Errorf("failed reload: status %d body %s", w.Code, w.Body)
	}
}

func TestChangesWithoutControl(t *testing.T) {
	s, _, _ := newAPI(t)
	if w := change(s, http.MethodPost, "/api/reload", "", true); w.Code != http.StatusNotImplemented {
		t.Errorf("status %d, want 501", w.Code)
	}
}

package apiclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"eventhorizon/internal/api"
	"eventhorizon/internal/control"
	"eventhorizon/internal/events"
	"eventhorizon/internal/policy"
	"eventhorizon/internal/rules"
	"eventhorizon/internal/stats"
)

// startAPI runs the real API on a random loopback port.
func startAPI(t *testing.T) (string, *stats.Stats, *events.Hub) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	st := stats.New(time.Now())
	hub := events.NewHub()
	h, err := api.New(addr, st, hub)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return addr, st, hub
}

func TestStats(t *testing.T) {
	addr, st, _ := startAPI(t)
	st.Record(time.Now(), "blocked", "10.0.0.2", "ads.x.com", "x.com", false)

	snap, err := New(addr).Stats(context.Background(), 5)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Totals.Blocked != 1 || snap.TopBlocked[0].Key != "ads.x.com" {
		t.Errorf("snapshot %+v", snap)
	}
}

func TestStreamDeliversBacklogAndLive(t *testing.T) {
	addr, _, hub := startAPI(t)
	hub.Publish(events.Event{Kind: "query", Name: "old.example"})

	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan events.Event, 10)
	done := make(chan error, 1)
	go func() { done <- New(addr).Stream(ctx, func(e events.Event) { got <- e }) }()

	if e := <-got; e.Name != "old.example" {
		t.Errorf("first = %+v", e)
	}
	hub.Publish(events.Event{Kind: "alert", Alert: "tunnel", Domain: "exfil.example"})
	select {
	case e := <-got:
		if e.Alert != "tunnel" {
			t.Errorf("live = %+v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("live event not received")
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("stop reason %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stream did not return after cancel")
	}
}

func TestStreamReportsServerGone(t *testing.T) {
	addr, _, _ := startAPI(t)
	c := New(addr)
	// Nothing listens here: the error must come back quickly, not hang.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	c.base = "http://" + dead

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.Stream(ctx, func(events.Event) {}); err == nil || ctx.Err() != nil {
		t.Errorf("err = %v, ctx = %v", err, ctx.Err())
	}
}

func TestBackoff(t *testing.T) {
	want := []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second, 5 * time.Second}
	for n, w := range want {
		if got := Backoff(n); got != w {
			t.Errorf("Backoff(%d) = %v, want %v", n, got, w)
		}
	}
}

// startControlledAPI runs the real API with the real controller and a
// rules file, so the whole change path is exercised.
func startControlledAPI(t *testing.T) (*Client, *control.Controller, func() *policy.Policy) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	h, err := api.New(addr, stats.New(time.Now()), events.NewHub())
	if err != nil {
		t.Fatal(err)
	}
	store, err := rules.Open(filepath.Join(t.TempDir(), "rules.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var current *policy.Policy
	ctl := control.New(store, func(p *policy.Policy) { mu.Lock(); current = p; mu.Unlock() })
	lists := policy.NewSet()
	lists.Add("tracker.example")
	ctl.SetLists(lists, nil)
	h.Control = ctl

	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return New(addr), ctl, func() *policy.Policy { mu.Lock(); defer mu.Unlock(); return current }
}

func TestRuleRoundTrip(t *testing.T) {
	c, _, active := startControlledAPI(t)
	ctx := context.Background()

	if _, err := c.SetRule(ctx, "Cdn.Tracker.Example", rules.Allow); err != nil {
		t.Fatal(err)
	}
	if d := active().Decide("img.cdn.tracker.example"); d.Blocked || !d.Mine {
		t.Errorf("allow rule not active: %+v", d)
	}
	list, err := c.Rules(ctx)
	if err != nil || len(list) != 1 || list[0].Domain != "cdn.tracker.example" {
		t.Errorf("rules %v, %v", list, err)
	}
	if err := c.RemoveRule(ctx, "cdn.tracker.example"); err != nil {
		t.Fatal(err)
	}
	if !active().Decide("img.cdn.tracker.example").Blocked {
		t.Error("list block not restored after removing the rule")
	}
}

func TestRuleErrorsCarryTheServerMessage(t *testing.T) {
	c, _, _ := startControlledAPI(t)
	_, err := c.SetRule(context.Background(), "not a domain", rules.Block)
	if err == nil || !strings.Contains(err.Error(), "invalid domain") {
		t.Errorf("err = %v", err)
	}
	if err := c.RemoveRule(context.Background(), "never.example"); err == nil {
		t.Error("removing a missing rule reported success")
	}
}

func TestReloadThroughTheMainLoop(t *testing.T) {
	c, ctl, _ := startControlledAPI(t)
	go func() { reply := <-ctl.Requests(); reply <- nil }()
	if err := c.Reload(context.Background()); err != nil {
		t.Errorf("reload: %v", err)
	}
}

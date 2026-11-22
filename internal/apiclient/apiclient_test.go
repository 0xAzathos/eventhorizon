package apiclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"eventhorizon/internal/api"
	"eventhorizon/internal/events"
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

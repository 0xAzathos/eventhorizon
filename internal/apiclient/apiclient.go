// Package apiclient talks to eventhorizon's local API (internal/api).
package apiclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"eventhorizon/internal/events"
	"eventhorizon/internal/stats"
)

// IdleTimeout ends a stream that has been silent this long. The server
// sends a heartbeat every 5 seconds, so silence means a dead connection.
const IdleTimeout = 15 * time.Second

type Client struct {
	base string
	http *http.Client
}

// New returns a client for an API at addr, e.g. "127.0.0.1:5380".
func New(addr string) *Client {
	// No overall timeout: the event stream is meant to stay open.
	// Each call bounds itself with its context instead.
	return &Client{base: "http://" + addr, http: &http.Client{}}
}

// Stats fetches one snapshot with up to n entries per top list.
func (c *Client) Stats(ctx context.Context, n int) (stats.Snapshot, error) {
	var snap stats.Snapshot
	url := fmt.Sprintf("%s/api/stats?top=%d", c.base, n)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return snap, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return snap, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return snap, fmt.Errorf("stats: %s", resp.Status)
	}
	err = json.NewDecoder(resp.Body).Decode(&snap)
	return snap, err
}

// ErrIdle means the stream went silent for longer than IdleTimeout.
var ErrIdle = errors.New("event stream went silent")

// Stream calls handle for every event until ctx ends or the connection
// drops. It always returns a non nil error explaining why it stopped.
func (c *Client) Stream(ctx context.Context, handle func(events.Event)) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/api/events", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("events: %s", resp.Status)
	}

	// Watchdog: every line pushes the deadline back; silence cancels.
	idle := time.AfterFunc(IdleTimeout, func() { cancel(ErrIdle) })
	defer idle.Stop()

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		idle.Reset(IdleTimeout)
		var e events.Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return fmt.Errorf("events: bad line: %w", err)
		}
		if e.Kind == "" {
			continue // heartbeat
		}
		handle(e)
	}
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return errors.New("event stream closed by server")
}

// Backoff returns how long to wait before reconnect attempt n (0 based):
// 0.5s, 1s, 2s, 4s, then 5s at most.
func Backoff(n int) time.Duration {
	d := 500 * time.Millisecond << min(n, 4)
	return min(d, 5*time.Second)
}

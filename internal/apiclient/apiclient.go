// Package apiclient talks to eventhorizon's local API (internal/api).
package apiclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"eventhorizon/internal/api"
	"eventhorizon/internal/events"
	"eventhorizon/internal/rules"
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

// errorFrom turns a non 2xx response into an error with the server's
// message when it sent one.
func errorFrom(resp *http.Response) error {
	var body struct {
		Error string `json:"error"`
	}
	if json.NewDecoder(resp.Body).Decode(&body) == nil && body.Error != "" {
		return errors.New(body.Error)
	}
	return fmt.Errorf("%s", resp.Status)
}

// do sends a change request; every change carries api.ChangeHeader.
func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	if method != http.MethodGet {
		req.Header.Set(api.ChangeHeader, "telescope")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return errorFrom(resp)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) Rules(ctx context.Context) ([]rules.Rule, error) {
	var out []rules.Rule
	err := c.do(ctx, http.MethodGet, "/api/rules", nil, &out)
	return out, err
}

// SetRule allows or blocks domain and its subdomains.
func (c *Client) SetRule(ctx context.Context, domain, action string) (rules.Rule, error) {
	var out rules.Rule
	err := c.do(ctx, http.MethodPost, "/api/rules", rules.Rule{Domain: domain, Action: action}, &out)
	return out, err
}

func (c *Client) RemoveRule(ctx context.Context, domain string) error {
	return c.do(ctx, http.MethodDelete, "/api/rules?domain="+url.QueryEscape(domain), nil, nil)
}

// Reload downloads the blocklists again; it can take a while.
func (c *Client) Reload(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/api/reload", nil, nil)
}

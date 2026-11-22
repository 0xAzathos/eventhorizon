// Package events fans out what the server does (queries, alerts) to any
// number of live viewers, such as the TUI.
//
// The one rule: publishing never blocks. DNS answers come first; a viewer
// that cannot keep up loses events instead of slowing anyone's lookups.
package events

import (
	"sync"
	"sync/atomic"
	"time"
)

// Event is either a query ("query") or an alert ("alert"). The JSON form
// is what the API streams, one event per line.
type Event struct {
	Time time.Time `json:"time"`
	Kind string    `json:"kind"`

	// Query fields.
	Proto      string `json:"proto,omitempty"`
	Client     string `json:"client,omitempty"`
	Name       string `json:"name,omitempty"`
	Type       string `json:"type,omitempty"`
	Action     string `json:"action,omitempty"` // allowed, blocked, cached, servfail
	Rule       string `json:"rule,omitempty"`
	Via        string `json:"via,omitempty"` // blocked through this CNAME target
	Suspicious string `json:"suspicious,omitempty"`
	TookMicros int64  `json:"took_us,omitempty"`

	// Alert fields.
	Alert    string   `json:"alert,omitempty"` // dga, tunnel
	Domain   string   `json:"domain,omitempty"`
	Count    int      `json:"count,omitempty"`
	Examples []string `json:"examples,omitempty"`
}

// BacklogSize is how many recent events a new viewer receives first, so
// the screen is not empty while waiting for traffic.
const BacklogSize = 200

// subBuffer is how many events may queue per viewer before dropping.
const subBuffer = 512

// Hub is safe for concurrent use. A nil *Hub ignores everything.
type Hub struct {
	mu      sync.Mutex
	subs    map[chan Event]struct{}
	backlog [BacklogSize]Event
	next    int // where the next event goes in backlog
	filled  int // how many backlog slots hold an event

	dropped atomic.Uint64
}

func NewHub() *Hub {
	return &Hub{subs: make(map[chan Event]struct{})}
}

// Publish hands e to every viewer without waiting for any of them.
func (h *Hub) Publish(e Event) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	h.backlog[h.next] = e
	h.next = (h.next + 1) % BacklogSize
	h.filled = min(h.filled+1, BacklogSize)

	for ch := range h.subs {
		select {
		case ch <- e:
		default:
			h.dropped.Add(1) // that viewer is behind; skip it
		}
	}
}

// Subscribe returns a channel of events, starting with the backlog
// (oldest first), and a function that ends the subscription.
func (h *Hub) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, subBuffer+BacklogSize)

	h.mu.Lock()
	for _, e := range h.recentLocked() {
		ch <- e // cannot block: the buffer has room for the whole backlog
	}
	h.subs[ch] = struct{}{}
	h.mu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subs, ch)
			h.mu.Unlock()
			close(ch)
		})
	}
}

// Recent returns the backlog, oldest first.
func (h *Hub) Recent() []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.recentLocked()
}

func (h *Hub) recentLocked() []Event {
	out := make([]Event, 0, h.filled)
	start := (h.next - h.filled + BacklogSize) % BacklogSize
	for i := range h.filled {
		out = append(out, h.backlog[(start+i)%BacklogSize])
	}
	return out
}

// Dropped counts events skipped for slow viewers since start.
func (h *Hub) Dropped() uint64 {
	if h == nil {
		return 0
	}
	return h.dropped.Load()
}

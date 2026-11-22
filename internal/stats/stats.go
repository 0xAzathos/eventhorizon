// Package stats keeps running totals for the dashboard: counters, a per
// second history for graphs, and top N lists, all in fixed memory.
package stats

import (
	"slices"
	"sync"
	"time"

	"eventhorizon/internal/upstream"
)

// HistorySeconds is how far back the per second series reaches.
const HistorySeconds = 120

type Totals struct {
	Queries    uint64 `json:"queries"`
	Allowed    uint64 `json:"allowed"`
	Blocked    uint64 `json:"blocked"`
	Cached     uint64 `json:"cached"`
	ServFail   uint64 `json:"servfail"`
	Suspicious uint64 `json:"suspicious"`
	Alerts     uint64 `json:"alerts"`
}

type Second struct {
	Unix    int64 `json:"t"`
	Queries int   `json:"queries"`
	Blocked int   `json:"blocked"`
}

type Snapshot struct {
	Started     time.Time `json:"started"`
	Totals      Totals    `json:"totals"`
	PerSecond   []Second  `json:"per_second"` // oldest first, HistorySeconds long
	TopBlocked  []Entry   `json:"top_blocked"`
	TopClients  []Entry   `json:"top_clients"`
	TopDomains  []Entry   `json:"top_domains"`
	Blocklist   int       `json:"blocklist_size"`
	CacheSize   int       `json:"cache_entries"`
	DroppedLive uint64    `json:"dropped_live_events"`

	// Filled in by the API from the upstream pool.
	Upstreams []upstream.Status `json:"upstreams"`
}

type Stats struct {
	mu      sync.Mutex
	started time.Time
	totals  Totals
	history [HistorySeconds]Second

	blocked *TopK
	clients *TopK
	domains *TopK
}

func New(now time.Time) *Stats {
	return &Stats{
		started: now,
		blocked: NewTopK(256),
		clients: NewTopK(256),
		domains: NewTopK(1024),
	}
}

// Record counts one answered query. registrable is the domain the name
// belongs to ("" if unknown), so top domains group "a.x.com" and "b.x.com".
// A nil *Stats records nothing.
func (s *Stats) Record(now time.Time, action, client, name, registrable string, suspicious bool) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.totals.Queries++
	switch action {
	case "allowed":
		s.totals.Allowed++
	case "blocked":
		s.totals.Blocked++
	case "cached":
		s.totals.Cached++
	case "servfail":
		s.totals.ServFail++
	}
	if suspicious {
		s.totals.Suspicious++
	}

	sec := s.bucket(now)
	sec.Queries++
	if action == "blocked" {
		sec.Blocked++
		s.blocked.Add(name)
	}
	s.clients.Add(client)
	if registrable != "" {
		s.domains.Add(registrable)
	}
}

func (s *Stats) RecordAlert() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.totals.Alerts++
	s.mu.Unlock()
}

// bucket returns the history slot for now's second, clearing it if it
// still holds a second from a previous lap around the ring.
func (s *Stats) bucket(now time.Time) *Second {
	t := now.Unix()
	b := &s.history[t%HistorySeconds]
	if b.Unix != t {
		*b = Second{Unix: t}
	}
	return b
}

// Snapshot copies the current state; n limits the top lists.
func (s *Stats) Snapshot(now time.Time, n int) Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	series := make([]Second, HistorySeconds)
	end := now.Unix()
	for i := range series {
		t := end - int64(HistorySeconds-1-i)
		b := s.history[t%HistorySeconds]
		if b.Unix != t {
			b = Second{Unix: t} // nothing happened that second
		}
		series[i] = b
	}

	return Snapshot{
		Started:    s.started,
		Totals:     s.totals,
		PerSecond:  series,
		TopBlocked: s.blocked.Top(n),
		TopClients: s.clients.Top(n),
		TopDomains: s.domains.Top(n),
	}
}

// Entry is one item of a top list. Count may overestimate by at most
// Error (see TopK).
type Entry struct {
	Key   string `json:"name"`
	Count uint64 `json:"count"`
	Error uint64 `json:"-"`
}

// TopK finds the most frequent keys in a stream using fixed memory: the
// Space-Saving algorithm (Metwally, Agrawal, El Abbadi, 2005).
//
// It keeps at most `capacity` counters. A new key, when full, takes over
// the counter with the smallest count and inherits it plus one. Every key
// that occurs more than total/capacity times is guaranteed to be tracked,
// and each count is high by at most the inherited amount (Error).
type TopK struct {
	capacity int
	entries  map[string]*Entry
}

func NewTopK(capacity int) *TopK {
	return &TopK{capacity: capacity, entries: make(map[string]*Entry, capacity)}
}

func (t *TopK) Add(key string) {
	if e, ok := t.entries[key]; ok {
		e.Count++
		return
	}
	if len(t.entries) < t.capacity {
		t.entries[key] = &Entry{Key: key, Count: 1}
		return
	}
	var smallest *Entry
	for _, e := range t.entries {
		if smallest == nil || e.Count < smallest.Count {
			smallest = e
		}
	}
	delete(t.entries, smallest.Key)
	t.entries[key] = &Entry{Key: key, Count: smallest.Count + 1, Error: smallest.Count}
}

// Top returns up to n entries, highest count first, ties by name.
func (t *TopK) Top(n int) []Entry {
	out := make([]Entry, 0, len(t.entries))
	for _, e := range t.entries {
		out = append(out, *e)
	}
	slices.SortFunc(out, func(a, b Entry) int {
		if a.Count != b.Count {
			if a.Count > b.Count {
				return -1
			}
			return 1
		}
		if a.Key < b.Key {
			return -1
		}
		if a.Key > b.Key {
			return 1
		}
		return 0
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

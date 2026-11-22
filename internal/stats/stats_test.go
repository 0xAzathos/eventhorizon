package stats

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func TestTotals(t *testing.T) {
	s := New(t0)
	s.Record(t0, "allowed", "10.0.0.2", "a.example.com", "example.com", false)
	s.Record(t0, "blocked", "10.0.0.2", "ads.tracker.com", "tracker.com", false)
	s.Record(t0, "cached", "10.0.0.3", "a.example.com", "example.com", true)
	s.Record(t0, "servfail", "10.0.0.3", "x.test", "x.test", false)
	s.RecordAlert()

	got := s.Snapshot(t0, 10).Totals
	want := Totals{Queries: 4, Allowed: 1, Blocked: 1, Cached: 1, ServFail: 1, Suspicious: 1, Alerts: 1}
	if got != want {
		t.Errorf("totals = %+v, want %+v", got, want)
	}
}

func TestPerSecondSeries(t *testing.T) {
	s := New(t0)
	s.Record(t0, "allowed", "c", "n", "", false)
	s.Record(t0, "blocked", "c", "n", "", false)
	s.Record(t0.Add(2*time.Second), "allowed", "c", "n", "", false)

	series := s.Snapshot(t0.Add(2*time.Second), 5).PerSecond
	if len(series) != HistorySeconds {
		t.Fatalf("len = %d", len(series))
	}
	last3 := series[HistorySeconds-3:]
	if last3[0].Queries != 2 || last3[0].Blocked != 1 || last3[1].Queries != 0 || last3[2].Queries != 1 {
		t.Errorf("last 3 seconds = %+v", last3)
	}
	if last3[2].Unix != t0.Unix()+2 {
		t.Errorf("newest second = %d", last3[2].Unix)
	}
}

func TestOldSecondsDoNotLeakIntoNewLap(t *testing.T) {
	s := New(t0)
	s.Record(t0, "allowed", "c", "n", "", false)
	// Exactly one lap later the same slot is reused for a new second.
	later := t0.Add(HistorySeconds * time.Second)
	series := s.Snapshot(later, 5).PerSecond
	for _, sec := range series {
		if sec.Queries != 0 {
			t.Fatalf("stale second shown: %+v", sec)
		}
	}
}

func TestTopListsGroupAndRank(t *testing.T) {
	s := New(t0)
	for range 3 {
		s.Record(t0, "blocked", "10.0.0.2", "ads.tracker.com", "tracker.com", false)
	}
	s.Record(t0, "blocked", "10.0.0.5", "pixel.ads.net", "ads.net", false)
	s.Record(t0, "allowed", "10.0.0.5", "www.example.com", "example.com", false)
	s.Record(t0, "allowed", "10.0.0.5", "cdn.example.com", "example.com", false)

	snap := s.Snapshot(t0, 10)
	if snap.TopBlocked[0] != (Entry{Key: "ads.tracker.com", Count: 3}) {
		t.Errorf("top blocked = %+v", snap.TopBlocked)
	}
	if snap.TopClients[0].Key != "10.0.0.2" || snap.TopClients[1].Key != "10.0.0.5" {
		t.Errorf("top clients = %+v", snap.TopClients)
	}
	if snap.TopDomains[0] != (Entry{Key: "tracker.com", Count: 3}) || snap.TopDomains[1] != (Entry{Key: "example.com", Count: 2}) {
		t.Errorf("top domains = %+v", snap.TopDomains)
	}
}

// Space-Saving guarantee: with capacity k, every key seen more than
// total/k times is in the list, and counts are high by at most Error.
func TestTopKFindsHeavyHitters(t *testing.T) {
	tk := NewTopK(50)
	rng := rand.New(rand.NewPCG(1, 2))
	truth := map[string]uint64{}
	add := func(k string) { tk.Add(k); truth[k]++ }

	const total = 100000
	for i := range total {
		switch {
		case i%10 == 0:
			add("heavy-1") // 10%
		case i%20 == 1:
			add("heavy-2") // 5%
		default:
			add(fmt.Sprintf("noise-%d", rng.IntN(20000)))
		}
	}

	top := tk.Top(2)
	if top[0].Key != "heavy-1" || top[1].Key != "heavy-2" {
		t.Fatalf("top = %+v", top)
	}
	for _, e := range tk.Top(50) {
		if e.Count < truth[e.Key] || e.Count-e.Error > truth[e.Key] {
			t.Errorf("%s: count %d error %d, true %d", e.Key, e.Count, e.Error, truth[e.Key])
		}
	}
	if len(tk.entries) > 50 {
		t.Errorf("grew to %d counters", len(tk.entries))
	}
}

func TestNilStats(t *testing.T) {
	var s *Stats
	s.Record(t0, "allowed", "c", "n", "", false)
	s.RecordAlert()
}

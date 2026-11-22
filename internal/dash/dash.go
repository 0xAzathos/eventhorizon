// Package dash holds the dashboard logic that does not depend on any
// terminal library: number formatting, the bar chart, and the event log.
// The TUI only adds colors and layout on top.
package dash

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"eventhorizon/internal/events"
	"eventhorizon/internal/stats"
)

// Count formats a counter compactly: 950, 1.2k, 12.3k, 123k, 1.2M.
func Count(n uint64) string {
	switch {
	case n < 1000:
		return fmt.Sprintf("%d", n)
	case n < 100_000:
		return trimZero(fmt.Sprintf("%.1f", float64(n)/1e3)) + "k"
	case n < 1_000_000:
		return fmt.Sprintf("%dk", n/1000)
	case n < 100_000_000:
		return trimZero(fmt.Sprintf("%.1f", float64(n)/1e6)) + "M"
	default:
		return fmt.Sprintf("%dM", n/1_000_000)
	}
}

func trimZero(s string) string { return strings.TrimSuffix(s, ".0") }

// Percent formats part/total: "0%", "4.2%", "42%".
func Percent(part, total uint64) string {
	if total == 0 {
		return "0%"
	}
	p := 100 * float64(part) / float64(total)
	if p < 10 && p > 0 {
		return trimZero(fmt.Sprintf("%.1f", p)) + "%"
	}
	return fmt.Sprintf("%.0f%%", p)
}

// Uptime formats a duration as its two largest units: "42s", "5m 03s",
// "4h 12m", "2d 3h".
func Uptime(d time.Duration) string {
	s := int(d.Seconds())
	switch {
	case s < 60:
		return fmt.Sprintf("%ds", s)
	case s < 3600:
		return fmt.Sprintf("%dm %02ds", s/60, s%60)
	case s < 86400:
		return fmt.Sprintf("%dh %02dm", s/3600, s%3600/60)
	default:
		return fmt.Sprintf("%dd %dh", s/86400, s%86400/3600)
	}
}

// Truncate shortens s to at most w characters, ending in "…" if cut.
func Truncate(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= w {
		return s
	}
	r := []rune(s)
	return string(r[:w-1]) + "…"
}

// Rate is the average queries per second over the last n complete
// seconds. The newest second is still filling up, so it is left out.
func Rate(series []stats.Second, n int) float64 {
	if len(series) < 2 || n <= 0 {
		return 0
	}
	complete := series[:len(series)-1]
	n = min(n, len(complete))
	sum := 0
	for _, s := range complete[len(complete)-n:] {
		sum += s.Queries
	}
	return float64(sum) / float64(n)
}

// CellKind tells the TUI how to color a chart cell.
type CellKind uint8

const (
	Empty   CellKind = iota
	Allowed          // part of the total, not blocked
	Blocked          // the blocked part of the bar
)

type Cell struct {
	Ch   rune
	Kind CellKind
}

// eighths draws partial blocks: index i is a block i/8 of a cell high.
var eighths = []rune{' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// Bars draws the last width seconds as a stacked bar chart, height rows
// tall, top row first. Each column is one second; its blocked queries are
// stacked at the bottom of the bar. Bars scale to the busiest second shown,
// which is returned as peak. Using eighth blocks gives height*8 levels.
func Bars(series []stats.Second, width, height int) (rows [][]Cell, peak int) {
	if width <= 0 || height <= 0 {
		return nil, 0
	}
	if len(series) > width {
		series = series[len(series)-width:]
	}
	for _, s := range series {
		peak = max(peak, s.Queries)
	}

	rows = make([][]Cell, height)
	for r := range rows {
		rows[r] = make([]Cell, width)
		for c := range rows[r] {
			rows[r][c] = Cell{' ', Empty}
		}
	}
	if peak == 0 {
		return rows, 0
	}

	levels := height * 8
	offset := width - len(series) // fewer seconds than columns: right align
	for i, s := range series {
		total := scale(s.Queries, peak, levels)
		blocked := scale(s.Blocked, peak, levels)
		col := offset + i
		for level := 0; level < height; level++ {
			bottom := level * 8 // eighths below this cell
			fill := min(max(total-bottom, 0), 8)
			if fill == 0 {
				break
			}
			kind := Allowed
			// The cell is blocked colored if blocked covers most of it.
			if blocked-bottom >= (fill+1)/2 {
				kind = Blocked
			}
			rows[height-1-level][col] = Cell{eighths[fill], kind}
		}
	}
	return rows, peak
}

// scale maps v in [0, peak] to [0, levels], rounding, but keeps any
// nonzero value at least one level so single queries stay visible.
func scale(v, peak, levels int) int {
	if v <= 0 {
		return 0
	}
	n := (v*levels + peak/2) / peak
	return max(n, 1)
}

// Filter selects which events the log shows.
type Filter int

const (
	ShowAll Filter = iota
	ShowBlocked
	ShowSuspicious
)

func (f Filter) String() string {
	return [...]string{"all", "blocked", "suspicious"}[f]
}

// Next cycles all -> blocked -> suspicious -> all.
func (f Filter) Next() Filter { return (f + 1) % 3 }

func (f Filter) Match(e events.Event) bool {
	switch f {
	case ShowBlocked:
		return e.Action == "blocked"
	case ShowSuspicious:
		return e.Suspicious != ""
	}
	return true
}

// Log keeps the most recent events in a fixed size ring.
type Log struct {
	items []events.Event
	next  int
	full  bool
}

func NewLog(capacity int) *Log {
	return &Log{items: make([]events.Event, capacity)}
}

func (l *Log) Add(e events.Event) {
	l.items[l.next] = e
	l.next = (l.next + 1) % len(l.items)
	if l.next == 0 {
		l.full = true
	}
}

func (l *Log) Len() int {
	if l.full {
		return len(l.items)
	}
	return l.next
}

func (l *Log) Clear() {
	l.next, l.full = 0, false
}

// Latest returns up to n events matching f, newest first.
func (l *Log) Latest(n int, f Filter) []events.Event {
	out := make([]events.Event, 0, n)
	for i := 1; i <= l.Len() && len(out) < n; i++ {
		e := l.items[(l.next-i+len(l.items))%len(l.items)]
		if f.Match(e) {
			out = append(out, e)
		}
	}
	return out
}

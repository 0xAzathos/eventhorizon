package dash

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/0xAzathos/eventhorizon/internal/events"
	"github.com/0xAzathos/eventhorizon/internal/stats"
)

func TestCount(t *testing.T) {
	cases := map[uint64]string{
		0: "0", 950: "950", 1000: "1k", 1234: "1.2k", 12345: "12.3k",
		123456: "123k", 1_234_567: "1.2M", 2_000_000: "2M", 456_000_000: "456M",
	}
	for n, want := range cases {
		if got := Count(n); got != want {
			t.Errorf("Count(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestPercent(t *testing.T) {
	cases := []struct {
		part, total uint64
		want        string
	}{
		{0, 0, "0%"}, {0, 10, "0%"}, {42, 1000, "4.2%"}, {1, 10, "10%"},
		{421, 1000, "42%"}, {10, 10, "100%"},
	}
	for _, c := range cases {
		if got := Percent(c.part, c.total); got != c.want {
			t.Errorf("Percent(%d, %d) = %q, want %q", c.part, c.total, got, c.want)
		}
	}
}

func TestUptime(t *testing.T) {
	cases := map[time.Duration]string{
		42 * time.Second:              "42s",
		5*time.Minute + 3*time.Second: "5m 03s",
		4*time.Hour + 12*time.Minute:  "4h 12m",
		51 * time.Hour:                "2d 3h",
	}
	for d, want := range cases {
		if got := Uptime(d); got != want {
			t.Errorf("Uptime(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestTruncate(t *testing.T) {
	cases := []struct {
		s    string
		w    int
		want string
	}{
		{"github.com", 20, "github.com"},
		{"github.com", 10, "github.com"},
		{"github.com", 7, "github…"},
		{"github.com", 1, "…"},
		{"github.com", 0, ""},
	}
	for _, c := range cases {
		if got := Truncate(c.s, c.w); got != c.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", c.s, c.w, got, c.want)
		}
	}
}

func secs(queries ...int) []stats.Second {
	out := make([]stats.Second, len(queries))
	for i, q := range queries {
		out[i] = stats.Second{Unix: int64(i), Queries: q}
	}
	return out
}

func TestRateSkipsCurrentSecond(t *testing.T) {
	// The last second (999) is still filling and must not count.
	s := secs(10, 20, 30, 999)
	if got := Rate(s, 2); got != 25 {
		t.Errorf("Rate = %v, want 25", got)
	}
	if got := Rate(s, 10); got != 20 {
		t.Errorf("Rate over more than available = %v, want 20", got)
	}
	if Rate(nil, 5) != 0 {
		t.Error("empty series")
	}
}

// render turns cells into text, with blocked cells shown as 'x' rows so
// tests can check both shape and color.
func render(rows [][]Cell) (shape, kinds string) {
	var a, b strings.Builder
	for _, row := range rows {
		for _, c := range row {
			a.WriteRune(c.Ch)
			b.WriteByte(" ab"[c.Kind])
		}
		a.WriteByte('\n')
		b.WriteByte('\n')
	}
	return a.String(), b.String()
}

func TestBarsShape(t *testing.T) {
	s := secs(0, 4, 8, 2)
	s[2].Blocked = 4 // half of the peak bar is blocked
	rows, peak := Bars(s, 4, 2)
	if peak != 8 {
		t.Fatalf("peak = %d", peak)
	}
	shape, kinds := render(rows)
	// 2 rows = 16 levels. 4/8 -> 8 levels (one full cell), 8 -> full
	// column, 2 -> 4 levels (half cell).
	wantShape := "  █ \n ██▄\n"
	// Column 2 is half blocked: bottom cell blocked (b), top allowed (a).
	wantKinds := "  a \n aba\n"
	if shape != wantShape {
		t.Errorf("shape:\n%q\nwant\n%q", shape, wantShape)
	}
	if kinds != wantKinds {
		t.Errorf("kinds:\n%q\nwant\n%q", kinds, wantKinds)
	}
}

func TestBarsKeepsSmallValuesVisible(t *testing.T) {
	rows, _ := Bars(secs(1000, 1), 2, 3)
	if rows[2][1].Ch == ' ' {
		t.Error("a single query vanished next to a 1000 query second")
	}
}

func TestColumns(t *testing.T) {
	cases := []struct{ seconds, width, shown, colW int }{
		{120, 80, 80, 1},   // narrow: newest 80 seconds, one column each
		{120, 120, 120, 1}, // exact fit
		{120, 1300, 120, 10},
		{0, 50, 0, 1},
		{5, 0, 0, 1},
	}
	for _, c := range cases {
		shown, colW := Columns(c.seconds, c.width)
		if shown != c.shown || colW != c.colW {
			t.Errorf("Columns(%d, %d) = %d, %d; want %d, %d", c.seconds, c.width, shown, colW, c.shown, c.colW)
		}
	}
}

func TestBarsWideColumnsWithGaps(t *testing.T) {
	rows, _ := Bars(secs(1, 2), 8, 1)
	shape, _ := render(rows)
	// 4 columns per second: a 3 wide bar plus a 1 column gap.
	if shape != "▄▄▄ ███ \n" {
		t.Errorf("shape %q", shape)
	}
}

func TestBarsRightAlignsLeftover(t *testing.T) {
	rows, _ := Bars(secs(5, 5), 5, 1) // 2 columns each, 1 column left over
	shape, _ := render(rows)
	if shape != " ████\n" {
		t.Errorf("shape %q", shape)
	}
}

func TestBarsUsesNewestSeconds(t *testing.T) {
	rows, peak := Bars(secs(100, 1, 2), 2, 1)
	if peak != 2 {
		t.Errorf("peak %d: older seconds outside the window must not scale the chart", peak)
	}
	if len(rows[0]) != 2 {
		t.Errorf("width %d", len(rows[0]))
	}
}

func TestBarsEmpty(t *testing.T) {
	rows, peak := Bars(secs(0, 0), 2, 2)
	if peak != 0 || rows[0][0].Ch != ' ' {
		t.Error("idle chart should be blank")
	}
	if r, _ := Bars(nil, 0, 5); r != nil {
		t.Error("zero width should give no rows")
	}
}

func TestLogNewestFirstAndFilter(t *testing.T) {
	l := NewLog(4)
	for i := range 6 { // wraps around: keeps 2,3,4,5
		e := events.Event{Name: fmt.Sprintf("n%d", i), Action: "allowed"}
		if i%2 == 0 {
			e.Action = "blocked"
		}
		if i == 5 {
			e.Suspicious = "dga"
		}
		l.Add(e)
	}
	names := func(es []events.Event) string {
		var s []string
		for _, e := range es {
			s = append(s, e.Name)
		}
		return strings.Join(s, ",")
	}
	if got := names(l.Latest(10, ShowAll)); got != "n5,n4,n3,n2" {
		t.Errorf("all = %s", got)
	}
	if got := names(l.Latest(10, ShowBlocked)); got != "n4,n2" {
		t.Errorf("blocked = %s", got)
	}
	if got := names(l.Latest(10, ShowSuspicious)); got != "n5" {
		t.Errorf("suspicious = %s", got)
	}
	if got := names(l.Latest(2, ShowAll)); got != "n5,n4" {
		t.Errorf("limit = %s", got)
	}
	l.Clear()
	if l.Len() != 0 || len(l.Latest(5, ShowAll)) != 0 {
		t.Error("clear left events behind")
	}
}

func TestFilterCycle(t *testing.T) {
	f := ShowAll
	var seen []string
	for range 4 {
		seen = append(seen, f.String())
		f = f.Next()
	}
	if strings.Join(seen, ",") != "all,blocked,suspicious,all" {
		t.Errorf("cycle = %v", seen)
	}
}

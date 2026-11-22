package detect

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"eventhorizon/internal/psl"
)

func defaultModel(t *testing.T) *Model {
	t.Helper()
	m, err := DefaultModel()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// newDetector uses the real model, a tiny popular list and a fake clock.
func newDetector(t *testing.T) (*Detector, *time.Time) {
	t.Helper()
	d := New(DefaultConfig(), defaultModel(t), map[string]bool{"google.com": true}, psl.Default)
	clock := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return clock }
	return d, &clock
}

func TestRealWordsScoreAboveRandom(t *testing.T) {
	m := defaultModel(t)
	thr := DefaultConfig().DGAThreshold
	for _, l := range []string{"wikipedia", "microsoft", "stackoverflow", "netflix", "booking", "eventhorizon"} {
		if s, _ := m.Score(l); s < thr {
			t.Errorf("%s scored %.2f, below threshold", l, s)
		}
	}
	for _, l := range []string{"xkq7v9zpl3wn", "qwzxjkvbnmpl", "nxlya47huo61czerb18o51"} {
		if s, _ := m.Score(l); s >= thr {
			t.Errorf("%s scored %.2f, not flagged", l, s)
		}
	}
	if _, ok := m.Score("under_score"); ok {
		t.Error("scored a label with characters outside the alphabet")
	}
}

// The embedded model must keep catching most real malware DGA output.
// Families built from dictionary words are expected to slip through.
func TestDGASamples(t *testing.T) {
	m := defaultModel(t)
	thr := DefaultConfig().DGAThreshold
	f, err := os.Open("testdata/dga_examples.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	hit, total := 0, 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "#") {
			continue
		}
		_, domain, _ := strings.Cut(sc.Text(), "\t")
		label := psl.Default.Split(domain).Label
		if s, ok := m.Score(label); ok && len(label) >= DefaultConfig().DGAMinLen {
			total++
			if s < thr {
				hit++
			}
		}
	}
	rate := float64(hit) / float64(total)
	t.Logf("detected %d of %d (%.1f%%)", hit, total, 100*rate)
	if rate < 0.70 {
		t.Errorf("detection rate %.1f%% fell below 70%%", 100*rate)
	}
}

func TestInspectExemptions(t *testing.T) {
	d, _ := newDetector(t)
	for _, name := range []string{
		"xkq7v9zpl3wn",                  // single label
		"1.0.0.127.in-addr.arpa",        // reverse lookup
		"_dns-sd._udp.xkq7v9zpl3wn.com", // service discovery
		"printer.local",                 // local network
		"xkq7v9zpl3wn.google.com",       // popular domain
		"xn--bcher-kva.com",             // IDN
		"short.com",                     // too short to judge
	} {
		if s := d.Inspect(name); s.Any() {
			t.Errorf("%s: flagged %+v", name, s)
		}
	}
	if s := d.Inspect("xkq7v9zpl3wn.com"); !s.DGALike || s.Registrable != "xkq7v9zpl3wn.com" {
		t.Errorf("random name not flagged: %+v", s)
	}
}

func tunnelName(i int) string {
	data := make([]byte, 40)
	for j := range data {
		data[j] = byte(i*31 + j*17 + j*j)
	}
	enc := hex.EncodeToString(data)
	return enc[:60] + "." + enc[60:] + ".t.exfil.example"
}

func TestInspectDataLike(t *testing.T) {
	d, _ := newDetector(t)
	if s := d.Inspect(tunnelName(1)); !s.DataLike || s.Registrable != "exfil.example" {
		t.Errorf("tunnel query not flagged: %+v", s)
	}
	for _, name := range []string{
		"www.example.com",
		"hamster-vpn-free-vpn-proxy-unlimited-secure.example.com", // long but low entropy
	} {
		if d.Inspect(name).DataLike {
			t.Errorf("%s flagged as data", name)
		}
	}
}

func TestDGABurstNeedsNXDOMAIN(t *testing.T) {
	d, clock := newDetector(t)
	random := []string{"xkq7v9zpl3wn", "qwzxjkvbnmpl", "zzkqxvbjwpfm", "pqxzvkjwbmtl", "jvqxzkwpbmfr", "kxzqvjwpbtml"}

	// Existing domains (NOERROR) never count.
	for _, l := range random {
		name := l + ".com"
		if a := d.Observe("10.0.0.5", name, d.Inspect(name), 0); a != nil {
			t.Fatalf("alert without NXDOMAIN: %+v", a)
		}
	}

	var alerts []Alert
	for i, l := range random[:5] {
		*clock = clock.Add(10 * time.Second)
		name := l + ".net"
		alerts = d.Observe("10.0.0.5", name, d.Inspect(name), 3)
		if i < 4 && alerts != nil {
			t.Fatalf("alerted after %d names", i+1)
		}
	}
	if len(alerts) != 1 || alerts[0].Kind != "dga" || alerts[0].Client != "10.0.0.5" || alerts[0].Count != 5 {
		t.Fatalf("alerts = %+v", alerts)
	}

	// Cooldown: the next one stays quiet.
	name := random[5] + ".net"
	if a := d.Observe("10.0.0.5", name, d.Inspect(name), 3); a != nil {
		t.Errorf("alerted again during cooldown: %+v", a)
	}
}

func TestDGAWindowAndDuplicates(t *testing.T) {
	d, clock := newDetector(t)
	obs := func(client, label string) []Alert {
		name := label + ".org"
		return d.Observe(client, name, d.Inspect(name), 3)
	}

	// The same name five times is one piece of evidence.
	for range 5 {
		if a := obs("10.0.0.7", "xkq7v9zpl3wn"); a != nil {
			t.Fatal("duplicates counted")
		}
	}
	// Spread out beyond the window: never five at once.
	for _, l := range []string{"qwzxjkvbnmpl", "zzkqxvbjwpfm", "pqxzvkjwbmtl", "jvqxzkwpbmfr", "kxzqvjwpbtml"} {
		*clock = clock.Add(2 * time.Minute)
		if a := obs("10.0.0.7", l); a != nil {
			t.Fatalf("alerted on spread out names: %+v", a)
		}
	}
	// Other clients have their own count.
	if a := obs("10.0.0.8", "xkq7v9zpl3wn"); a != nil {
		t.Error("clients share a counter")
	}
}

func TestTunnelBurst(t *testing.T) {
	d, clock := newDetector(t)
	var alerts []Alert
	for i := range 10 {
		*clock = clock.Add(time.Second)
		name := tunnelName(i)
		alerts = d.Observe("10.0.0.9", name, d.Inspect(name), 0)
		if i < 9 && alerts != nil {
			t.Fatalf("alerted after %d queries", i+1)
		}
	}
	if len(alerts) != 1 || alerts[0].Kind != "tunnel" || alerts[0].Domain != "exfil.example" {
		t.Fatalf("alerts = %+v", alerts)
	}
}

func TestSweepForgetsOldKeys(t *testing.T) {
	d, clock := newDetector(t)
	for i := range 10001 {
		// A different registrable domain each time: c0.example, c1.example...
		sub := strings.TrimSuffix(tunnelName(i), ".t.exfil.example")
		name := fmt.Sprintf("%s.c%d.example", sub, i)
		d.Observe("10.0.0.1", name, d.Inspect(name), 0)
		if i == 5000 {
			*clock = clock.Add(time.Hour) // everything before this expires
		}
	}
	d.mu.Lock()
	n := len(d.tunnel)
	d.mu.Unlock()
	if n == 0 || n > 5001 {
		t.Errorf("tracked %d domains, expected the expired ones swept", n)
	}
}

func TestEntropy(t *testing.T) {
	cases := map[string]float64{
		"":                 0,
		"aaaa":             0,
		"ab":               1,
		"0123456789abcdef": 4,
	}
	for s, want := range cases {
		if got := Entropy(s); math.Abs(got-want) > 1e-9 {
			t.Errorf("Entropy(%q) = %v, want %v", s, got, want)
		}
	}
}

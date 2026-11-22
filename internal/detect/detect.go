// Package detect finds signs of malware in DNS traffic that no blocklist
// knows about yet. It looks at behavior over time, not single names:
//
// DGA: malware with a Domain Generation Algorithm tries many random
// looking names, and almost none of them exist. One random looking name is
// weak evidence (plenty of real sites have odd names), but one device
// getting NXDOMAIN for several of them within minutes is a strong signal.
//
// Tunneling: data smuggled out inside queries shows up as long, high
// entropy subdomains. A website has a handful of hostnames; a tunnel sends
// a stream of unique ones under the same domain.
package detect

import (
	"math"
	"strings"
	"sync"
	"time"

	"eventhorizon/internal/psl"
)

type Config struct {
	DGAThreshold float64       // trigram score below this is random looking
	DGAMinLen    int           // shorter labels are not judged
	DGABurst     int           // random NXDOMAINs from one client...
	DGAWindow    time.Duration // ...within this window raise an alert

	TunnelMinChars   int     // subdomain characters, dots excluded
	TunnelMinLabel   int     // longest single label in the subdomain
	TunnelMinEntropy float64 // bits per character
	TunnelMaxScore   float64 // longest label must also look random to the model
	TunnelBurst      int     // unique data like subdomains of one domain...
	TunnelWindow     time.Duration

	Cooldown time.Duration // quiet period after an alert for the same key
}

// DefaultConfig values come from measurements on Chrome UX Report sites,
// malware DGA samples and simulated tunnels; see cmd/train and README.
func DefaultConfig() Config {
	return Config{
		DGAThreshold:     -3.6,
		DGAMinLen:        8,
		DGABurst:         5,
		DGAWindow:        5 * time.Minute,
		TunnelMinChars:   40,
		TunnelMinLabel:   30,
		TunnelMinEntropy: 3.5,
		TunnelMaxScore:   -3.2,
		TunnelBurst:      10,
		TunnelWindow:     time.Minute,
		Cooldown:         10 * time.Minute,
	}
}

// Signals are what a single name looks like, before any behavior.
type Signals struct {
	Registrable string
	DGALike     bool
	DGAScore    float64
	DataLike    bool // subdomain looks like encoded data
}

func (s Signals) Any() bool { return s.DGALike || s.DataLike }

// Label is a short tag for logs: "dga", "tunnel", "dga+tunnel" or "".
func (s Signals) Label() string {
	switch {
	case s.DGALike && s.DataLike:
		return "dga+tunnel"
	case s.DGALike:
		return "dga"
	case s.DataLike:
		return "tunnel"
	}
	return ""
}

// Alert is a behavioral finding worth a human's attention.
type Alert struct {
	Kind     string // "dga" or "tunnel"
	Client   string // the device, without port
	Domain   string // for tunnels: the domain receiving the data
	Count    int
	Examples []string
}

type event struct {
	at   time.Time
	name string
}

type Detector struct {
	cfg     Config
	model   *Model
	popular map[string]bool
	psl     *psl.List
	now     func() time.Time // replaceable in tests

	mu        sync.Mutex
	dga       map[string][]event // client -> random NXDOMAINs
	tunnel    map[string][]event // registrable -> data like names
	lastAlert map[string]time.Time
}

func New(cfg Config, model *Model, popular map[string]bool, list *psl.List) *Detector {
	return &Detector{
		cfg:       cfg,
		model:     model,
		popular:   popular,
		psl:       list,
		now:       time.Now,
		dga:       make(map[string][]event),
		tunnel:    make(map[string][]event),
		lastAlert: make(map[string]time.Time),
	}
}

// Names that are never judged: reverse lookups, local names, service
// discovery records with underscores.
var exemptSuffixes = []string{".arpa", ".local", ".localhost", ".internal", ".lan", ".home"}

// Inspect judges one name on its own. It is cheap and keeps no state.
// A nil *Detector inspects nothing.
func (d *Detector) Inspect(name string) Signals {
	if d == nil || !strings.Contains(name, ".") || strings.Contains(name, "_") {
		return Signals{}
	}
	for _, suf := range exemptSuffixes {
		if strings.HasSuffix(name, suf) {
			return Signals{}
		}
	}
	p := d.psl.Split(name)
	s := Signals{Registrable: p.Registrable}
	if p.Registrable == "" || d.popular[p.Registrable] {
		return s
	}

	// IDN labels (xn--) are encoded Unicode and look random by nature.
	if len(p.Label) >= d.cfg.DGAMinLen && !strings.HasPrefix(p.Label, "xn--") {
		if score, ok := d.model.Score(p.Label); ok {
			s.DGAScore = score
			s.DGALike = score < d.cfg.DGAThreshold
		}
	}

	if p.Sub != "" {
		s.DataLike = d.dataLike(p.Sub)
	}
	return s
}

// dataLike: long, high entropy, and random looking to the model. Length
// and entropy alone also match long readable hostnames like
// "free-vpn-proxy-unlimited-secure"; encoded data never reads like words.
func (d *Detector) dataLike(sub string) bool {
	flat := strings.ReplaceAll(sub, ".", "")
	if len(flat) < d.cfg.TunnelMinChars || Entropy(flat) < d.cfg.TunnelMinEntropy {
		return false
	}
	longest := ""
	for _, l := range strings.Split(sub, ".") {
		if len(l) > len(longest) {
			longest = l
		}
	}
	if len(longest) < d.cfg.TunnelMinLabel {
		return false
	}
	score, ok := d.model.Score(longest)
	return ok && score < d.cfg.TunnelMaxScore
}

// Observe records a finished query and returns any alert it completes.
// rcode is the upstream reply code (3 = NXDOMAIN).
func (d *Detector) Observe(client, name string, sig Signals, rcode int) []Alert {
	if d == nil || !sig.Any() {
		return nil
	}
	now := d.now()

	d.mu.Lock()
	defer d.mu.Unlock()

	var alerts []Alert
	if sig.DGALike && rcode == 3 {
		events := record(d.dga[client], now, d.cfg.DGAWindow, name)
		d.dga[client] = events
		if len(events) >= d.cfg.DGABurst && d.ready("dga|"+client, now) {
			alerts = append(alerts, Alert{
				Kind: "dga", Client: client, Count: len(events), Examples: names(events, 5),
			})
		}
	}
	if sig.DataLike {
		events := record(d.tunnel[sig.Registrable], now, d.cfg.TunnelWindow, name)
		d.tunnel[sig.Registrable] = events
		if len(events) >= d.cfg.TunnelBurst && d.ready("tunnel|"+sig.Registrable, now) {
			alerts = append(alerts, Alert{
				Kind: "tunnel", Client: client, Domain: sig.Registrable,
				Count: len(events), Examples: names(events, 3),
			})
		}
	}
	if len(d.dga)+len(d.tunnel) > 10000 {
		d.sweep(now)
	}
	return alerts
}

// ready reports whether key may alert again, and starts its cooldown.
func (d *Detector) ready(key string, now time.Time) bool {
	if last, ok := d.lastAlert[key]; ok && now.Sub(last) < d.cfg.Cooldown {
		return false
	}
	d.lastAlert[key] = now
	return true
}

// record drops events older than the window and adds name unless it is
// already there: repeats of one name are one piece of evidence.
func record(events []event, now time.Time, window time.Duration, name string) []event {
	keep := events[:0]
	seen := false
	for _, e := range events {
		if now.Sub(e.at) < window {
			keep = append(keep, e)
			seen = seen || e.name == name
		}
	}
	if !seen {
		keep = append(keep, event{now, name})
	}
	return keep
}

// sweep forgets keys whose events have all expired, so memory stays
// bounded when traffic touches many domains.
func (d *Detector) sweep(now time.Time) {
	for k, ev := range d.dga {
		if len(ev) == 0 || now.Sub(ev[len(ev)-1].at) >= d.cfg.DGAWindow {
			delete(d.dga, k)
		}
	}
	for k, ev := range d.tunnel {
		if len(ev) == 0 || now.Sub(ev[len(ev)-1].at) >= d.cfg.TunnelWindow {
			delete(d.tunnel, k)
		}
	}
	for k, at := range d.lastAlert {
		if now.Sub(at) >= d.cfg.Cooldown {
			delete(d.lastAlert, k)
		}
	}
}

func names(events []event, n int) []string {
	out := make([]string, 0, n)
	for i := len(events) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, events[i].name)
	}
	return out
}

// Entropy is the Shannon entropy of s in bits per character: about 4 for
// hex, 5 for base32, lower for natural words.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

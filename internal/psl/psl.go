// Package psl finds the registrable part of a domain name using the Public
// Suffix List (https://publicsuffix.org/list/).
//
// For "ads.tracker.example.co.uk":
//
//	suffix      co.uk                  (anyone can register under it)
//	registrable example.co.uk          (what someone actually registered)
//	label       example
//	sub         ads.tracker            (chosen freely by the owner)
//
// Matching rules (from publicsuffix.org/list, "Algorithm"):
//  1. A rule matches when its labels equal the rightmost labels of the
//     name; "*" in a rule matches any one label.
//  2. Exception rules ("!city.kawasaki.jp") win over everything.
//  3. Otherwise the matching rule with the most labels wins.
//  4. If nothing matches, the rule is "*": the last label is the suffix.
//  5. For an exception, drop its leftmost label to get the suffix.
package psl

import (
	"bufio"
	_ "embed"
	"strings"

	"github.com/0xAzathos/eventhorizon/internal/punycode"
)

//go:embed public_suffix_list.dat
var listData string

// List holds parsed rules. The zero value matches nothing but the default
// "*" rule.
type List struct {
	normal     map[string]bool // "co.uk"
	wildcard   map[string]bool // "*.ck" is stored as "ck"
	exceptions map[string]bool // "!www.ck" is stored as "www.ck"
}

// Default is the list embedded at build time.
var Default = mustParse(listData)

func mustParse(data string) *List {
	l, err := Parse(data)
	if err != nil {
		panic("psl: embedded list: " + err.Error())
	}
	return l
}

// Parse reads the .dat format: one rule per line, "//" starts a comment.
// Unicode rules are stored in their punycode (xn--) form, because that is
// what appears in DNS queries.
func Parse(data string) (*List, error) {
	l := &List{
		normal:     make(map[string]bool),
		wildcard:   make(map[string]bool),
		exceptions: make(map[string]bool),
	}
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "//") {
			continue
		}
		rule := fields[0]

		labels := strings.Split(rule, ".")
		for i, lab := range labels {
			if lab == "*" || lab == "!" {
				continue
			}
			prefix := ""
			if i == 0 && strings.HasPrefix(lab, "!") {
				prefix, lab = "!", lab[1:]
			}
			ascii, err := punycode.ToASCII(lab)
			if err != nil {
				return nil, err
			}
			labels[i] = prefix + ascii
		}
		rule = strings.Join(labels, ".")

		switch {
		case strings.HasPrefix(rule, "!"):
			l.exceptions[rule[1:]] = true
		case strings.HasPrefix(rule, "*."):
			l.wildcard[rule[2:]] = true
		default:
			l.normal[rule] = true
		}
	}
	return l, sc.Err()
}

// Parts is a name split at its registrable domain.
type Parts struct {
	Suffix      string // public suffix, e.g. "co.uk"
	Registrable string // suffix plus one label; "" if the name is a suffix
	Label       string // the label just left of the suffix, e.g. "example"
	Sub         string // everything left of Registrable, may be ""
}

// Split expects a lowercase name without a trailing dot, as produced by
// dnsmsg.Parse.
func (l *List) Split(name string) Parts {
	if name == "" {
		return Parts{}
	}
	labels := strings.Split(name, ".")
	n := l.suffixLabels(labels)

	p := Parts{Suffix: strings.Join(labels[len(labels)-n:], ".")}
	if n >= len(labels) {
		return p // the whole name is a public suffix
	}
	regStart := len(labels) - n - 1
	p.Label = labels[regStart]
	p.Registrable = strings.Join(labels[regStart:], ".")
	p.Sub = strings.Join(labels[:regStart], ".")
	return p
}

// suffixLabels returns how many labels from the right form the suffix.
func (l *List) suffixLabels(labels []string) int {
	// Exceptions first: they override any other match.
	for i := range labels {
		if l.exceptions[strings.Join(labels[i:], ".")] {
			return len(labels) - i - 1
		}
	}
	// Longest match first, so the first hit has the most labels.
	for i := range labels {
		if l.normal[strings.Join(labels[i:], ".")] {
			return len(labels) - i
		}
		// labels[i] plays the "*" of a wildcard rule.
		if i+1 < len(labels) && l.wildcard[strings.Join(labels[i+1:], ".")] {
			return len(labels) - i
		}
	}
	return 1 // default rule "*"
}

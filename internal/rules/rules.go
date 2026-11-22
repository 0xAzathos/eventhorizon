// Package rules stores the user's own allow and block decisions, made from
// the TUI or the API, in a small text file that survives restarts:
//
//	# eventhorizon rules
//	allow example.com
//	block tracker.example
//
// Each domain has at most one rule; setting a new one replaces the old.
// Rules cover the domain and all of its subdomains, like list entries.
package rules

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"eventhorizon/internal/policy"
)

const (
	Allow = "allow"
	Block = "block"
)

type Rule struct {
	Domain string `json:"domain"`
	Action string `json:"action"` // "allow" or "block"
}

type Store struct {
	path  string
	mu    sync.Mutex
	rules map[string]string // domain -> action
}

// Open loads the rules file at path. A missing file is an empty store; it
// is created on the first change.
func Open(path string) (*Store, error) {
	s := &Store{path: path, rules: make(map[string]string)}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			return nil, fmt.Errorf("%s:%d: want \"allow DOMAIN\" or \"block DOMAIN\"", path, n)
		}
		domain, err := Normalize(fields[1])
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, n, err)
		}
		if fields[0] != Allow && fields[0] != Block {
			return nil, fmt.Errorf("%s:%d: unknown action %q", path, n, fields[0])
		}
		s.rules[domain] = fields[0]
	}
	return s, sc.Err()
}

// Normalize lowercases a domain, drops a trailing dot and checks that it
// is a plausible hostname: labels of letters, digits, '-' and '_', each
// 1 to 63 characters, 253 characters in total.
func Normalize(domain string) (string, error) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if d == "" || len(d) > 253 {
		return "", fmt.Errorf("invalid domain %q", domain)
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid domain %q", domain)
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", fmt.Errorf("invalid domain %q", domain)
			}
		}
	}
	return d, nil
}

// Set adds or replaces the rule for domain and saves the file.
func (s *Store) Set(domain, action string) (Rule, error) {
	if action != Allow && action != Block {
		return Rule{}, fmt.Errorf("action must be %q or %q", Allow, Block)
	}
	d, err := Normalize(domain)
	if err != nil {
		return Rule{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, had := s.rules[d]
	s.rules[d] = action
	if err := s.saveLocked(); err != nil {
		// Keep memory and file in agreement.
		if had {
			s.rules[d] = old
		} else {
			delete(s.rules, d)
		}
		return Rule{}, err
	}
	return Rule{Domain: d, Action: action}, nil
}

// Remove deletes the rule for domain. It reports false if there was none.
func (s *Store) Remove(domain string) (bool, error) {
	d, err := Normalize(domain)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	action, ok := s.rules[d]
	if !ok {
		return false, nil
	}
	delete(s.rules, d)
	if err := s.saveLocked(); err != nil {
		s.rules[d] = action
		return false, err
	}
	return true, nil
}

// List returns all rules sorted by domain.
func (s *Store) List() []Rule {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Rule, 0, len(s.rules))
	for d, a := range s.rules {
		out = append(out, Rule{Domain: d, Action: a})
	}
	slices.SortFunc(out, func(a, b Rule) int { return strings.Compare(a.Domain, b.Domain) })
	return out
}

// Sets builds fresh policy sets from the rules.
func (s *Store) Sets() (allow, block *policy.Set) {
	allow, block = policy.NewSet(), policy.NewSet()
	for _, r := range s.List() {
		if r.Action == Allow {
			allow.Add(r.Domain)
		} else {
			block.Add(r.Domain)
		}
	}
	return allow, block
}

// saveLocked writes the file atomically: a temporary file renamed into
// place, so a crash never leaves half a rules file.
func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".rules-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename

	w := bufio.NewWriter(tmp)
	w.WriteString("# eventhorizon rules: your own allow and block decisions.\n")
	w.WriteString("# Each rule covers the domain and all its subdomains.\n")
	domains := make([]string, 0, len(s.rules))
	for d := range s.rules {
		domains = append(domains, d)
	}
	slices.Sort(domains)
	for _, d := range domains {
		fmt.Fprintf(w, "%s %s\n", s.rules[d], d)
	}
	if err := w.Flush(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

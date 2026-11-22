package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sub", "rules.txt")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return s, path
}

func TestSetPersistsAndReloads(t *testing.T) {
	s, path := newStore(t)
	if _, err := s.Set("GitHub.com.", Allow); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set("tracker.example", Block); err != nil {
		t.Fatal(err)
	}

	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got := again.List()
	want := []Rule{{"github.com", Allow}, {"tracker.example", Block}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("reloaded %v, want %v", got, want)
	}
}

func TestOneRulePerDomain(t *testing.T) {
	s, _ := newStore(t)
	s.Set("site.example", Block)
	s.Set("site.example", Allow) // changing your mind replaces the rule
	if l := s.List(); len(l) != 1 || l[0].Action != Allow {
		t.Errorf("rules %v", l)
	}
}

func TestRemove(t *testing.T) {
	s, path := newStore(t)
	s.Set("a.example", Block)
	if ok, err := s.Remove("A.example"); !ok || err != nil {
		t.Fatalf("remove: %v %v", ok, err)
	}
	if ok, _ := s.Remove("a.example"); ok {
		t.Error("removed a rule that was not there")
	}
	again, _ := Open(path)
	if len(again.List()) != 0 {
		t.Error("removal not saved")
	}
}

func TestSets(t *testing.T) {
	s, _ := newStore(t)
	s.Set("good.example", Allow)
	s.Set("bad.example", Block)
	allow, block := s.Sets()
	if _, ok := allow.Match("cdn.good.example"); !ok {
		t.Error("allow rule should cover subdomains")
	}
	if _, ok := block.Match("bad.example"); !ok {
		t.Error("block rule missing")
	}
	if _, ok := block.Match("good.example"); ok {
		t.Error("allow rule ended up in the block set")
	}
}

func TestValidation(t *testing.T) {
	s, _ := newStore(t)
	for _, bad := range []string{"", ".", "a..b", "-bad.example", "bad-.example", "spa ce.com", "a/b.com", strings.Repeat("a", 64) + ".com"} {
		if _, err := s.Set(bad, Block); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
	if _, err := s.Set("ok.example", "maybe"); err == nil {
		t.Error("accepted an unknown action")
	}
	for _, good := range []string{"localhost", "_dmarc.example.com", "xn--bcher-kva.example"} {
		if _, err := s.Set(good, Block); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
}

func TestOpenErrors(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"too many fields": "block a.example extra\n",
		"bad action":      "deny a.example\n",
		"bad domain":      "block -x.example\n",
	} {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "_"))
		os.WriteFile(path, []byte(content), 0o644)
		if _, err := Open(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	path := filepath.Join(dir, "ok")
	os.WriteFile(path, []byte("# comment\n\nallow a.example # trailing comment\n"), 0o644)
	if s, err := Open(path); err != nil || len(s.List()) != 1 {
		t.Errorf("comments: %v", err)
	}
}

func TestSaveLeavesNoTempFiles(t *testing.T) {
	s, path := newStore(t)
	s.Set("a.example", Block)
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("files: %v", entries)
	}
}

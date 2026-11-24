package paths

import (
	"errors"
	"path/filepath"
	"testing"
)

// fake builds a System with the given environment and existing files.
func fake(env map[string]string, existing ...string) System {
	return System{
		Getenv: func(key string) string { return env[key] },
		Exists: func(path string) bool {
			for _, e := range existing {
				if e == path {
					return true
				}
			}
			return false
		},
		ConfigDir: func() (string, error) { return filepath.Join("home", "config"), nil },
		CacheDir:  func() (string, error) { return filepath.Join("home", "cache"), nil },
	}
}

func TestFreshInstallUsesUserFolders(t *testing.T) {
	got := fake(nil).Default()
	want := Dirs{
		Rules:     filepath.Join("home", "config", "eventhorizon", "rules.txt"),
		ListCache: filepath.Join("home", "cache", "eventhorizon", "lists"),
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestSystemdWins(t *testing.T) {
	got := fake(map[string]string{"STATE_DIRECTORY": "/var/lib/eventhorizon"}, legacyRules).Default()
	want := Dirs{Rules: filepath.Join("/var/lib/eventhorizon", "rules.txt"), ListCache: "/var/lib/eventhorizon"}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestOldFilesKeepWorking(t *testing.T) {
	got := fake(nil, legacyRules).Default()
	if got.Rules != legacyRules {
		t.Errorf("rules: got %s, want the existing %s", got.Rules, legacyRules)
	}
	if want := filepath.Join("home", "cache", "eventhorizon", "lists"); got.ListCache != want {
		t.Errorf("list cache: got %s, want %s", got.ListCache, want)
	}
}

func TestNoHomeFallsBackToCurrentFolder(t *testing.T) {
	s := fake(nil)
	s.ConfigDir = func() (string, error) { return "", errors.New("no home") }
	s.CacheDir = s.ConfigDir
	if got := s.Default(); got != (Dirs{Rules: legacyRules, ListCache: legacyListCache}) {
		t.Fatalf("got %+v", got)
	}
}

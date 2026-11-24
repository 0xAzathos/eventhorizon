// Package paths decides where eventhorizon keeps its files by default:
// your own rules, and the saved copies of downloaded blocklists.
package paths

import (
	"os"
	"path/filepath"
)

// The folder names older versions used, relative to the current folder.
const (
	legacyRules     = "eventhorizon-rules.txt"
	legacyListCache = ".list-cache"
)

// Dirs holds the default locations.
type Dirs struct {
	Rules     string // the rules file
	ListCache string // folder for saved blocklists
}

// System is what Default needs to know about the machine.
// Tests fill it with fakes; OS return the real thing.
type System struct {
	Getenv    func(key string) string
	Exists    func(path string) bool
	ConfigDir func() (string, error)
	CacheDir  func() (string, error)
}

// OS describes the machine this runs on.
func OS() System {
	return System{
		Getenv: os.Getenv,
		Exists: func(path string) bool {
			_, err := os.Stat(path)
			return err == nil
		},
		ConfigDir: os.UserConfigDir,
		CacheDir:  os.UserCacheDir,
	}
}

// Default picks the locations, first match wins:
//
//  1. Running as a systemd service: the StateDirectory systemd made.
//  2. Files an odler version left in the current folder:
//     keep using them, so upgrading never loses your rules.
//  3. Otherwise the per user folders each OS expects:
//     On linux ~/.config/eventhorizon and ~/.cache/eventhorizon,
//     On macOS ~/Library/Application Support and ~/Library/Caches,
//     On Windows %AppData% and %LocalAppData%.
//
// If the OS cannot say where those are, the current folder is used.
func (s System) Default() Dirs {
	if dir := s.Getenv("STATE_DIRECTORY"); dir != "" {
		return Dirs{Rules: filepath.Join(dir, "rules.txt"), ListCache: dir}
	}
	d := Dirs{Rules: legacyRules, ListCache: legacyListCache}
	if !s.Exists(legacyRules) {
		if dir, err := s.ConfigDir(); err == nil {
			d.Rules = filepath.Join(dir, "eventhorizon", "rules.txt")
		}
	}
	if !s.Exists(legacyListCache) {
		if dir, err := s.CacheDir(); err == nil {
			d.ListCache = filepath.Join(dir, "eventhorizon", "lists")
		}
	}
	return d
}

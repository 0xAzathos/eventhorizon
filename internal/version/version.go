// Package version reports which build of eventhorizon is running.
package version

import "runtime/debug"

// Version is stamped in by release builds:
//
//	go build -ldflags "-X github.com/0xAzathos/eventhorizon/internal/version.Version=v0.1.0"
var Version = "dev"

// String returns the stamped version, else the module version Go records
// for "go install ...@v0.1.0", else "dev" plus the commit when known.
func String() string {
	if Version != "dev" {
		return Version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return Version
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && len(s.Value) >= 7 {
			return "dev-" + s.Value[:7]
		}
	}
	return Version
}

package dnsmsg

import (
	"encoding/hex"
	"testing"
)

// Everything in this package reads bytes straight from the network. These
// fuzz tests feed it mutated packets and fail on any panic.
//
//	go test -fuzz FuzzParse -fuzztime 30s ./internal/dnsmsg

func seeds(f *testing.F) {
	f.Add(buildQuery(1, "example.com", TypeA))
	if b, err := hex.DecodeString(cloaked); err == nil {
		f.Add(b)
	}
	f.Add([]byte{})
	f.Add(make([]byte, 12))
}

func FuzzParse(f *testing.F) {
	seeds(f)
	f.Fuzz(func(t *testing.T, msg []byte) {
		if q, err := Parse(msg); err == nil {
			q.Blocked()
			q.Question()
		}
		ErrorResponse(msg, RcodeFormErr)
	})
}

func FuzzParseResponse(f *testing.F) {
	seeds(f)
	f.Fuzz(func(t *testing.T, msg []byte) {
		ParseResponse(msg)
		CNAMETargets(msg)
		Truncate(msg)
	})
}

func FuzzReadName(f *testing.F) {
	seeds(f)
	f.Fuzz(func(t *testing.T, msg []byte) {
		for off := range min(len(msg), 64) {
			name, next, err := ReadName(msg, off)
			if err == nil && (next <= off || next > len(msg) || len(name) > 253) {
				t.Fatalf("off %d: name %q next %d", off, name, next)
			}
		}
	})
}

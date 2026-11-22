package dnsmsg

import (
	"encoding/hex"
	"errors"
	"slices"
	"testing"
)

// cloaked is a real response produced by dnspython (an independent DNS
// implementation) with its own name compression: metrics.shop.example is
// a CNAME for shop.edge.tracker.net, which is a CNAME for a12.tracker.net.
// The second target is stored as "a12" plus a pointer into the first.
const cloaked = "424281000001000300000000074d6574726963730453686f70074578616d706c65" +
	"0000010001c00c000500010000012c00170473686f70046564676507747261636b" +
	"6572036e657400c032000500010000012c000603613132c03cc055000100010000" +
	"003c0004cb007107"

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCNAMETargetsFromRealPacket(t *testing.T) {
	got, err := CNAMETargets(mustHex(t, cloaked))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"shop.edge.tracker.net", "a12.tracker.net"}
	if !slices.Equal(got, want) {
		t.Errorf("targets = %v, want %v", got, want)
	}
}

func TestReadNamePlainAndCompressed(t *testing.T) {
	msg := mustHex(t, cloaked)

	// The question name, stored in full and in mixed case.
	name, next, err := ReadName(msg, 12)
	if err != nil || name != "metrics.shop.example" || next != 34 {
		t.Errorf("question: %q next %d err %v", name, next, err)
	}

	// The first answer's owner is only a pointer (c0 0c) to the question.
	name, next, err = ReadName(msg, 38)
	if err != nil || name != "metrics.shop.example" || next != 40 {
		t.Errorf("pointer owner: %q next %d err %v", name, next, err)
	}
}

func TestReadNameRejectsLoops(t *testing.T) {
	header := make([]byte, 12)

	self := append(append([]byte(nil), header...), 0xC0, 12) // points at itself
	if _, _, err := ReadName(self, 12); !errors.Is(err, ErrBadName) {
		t.Errorf("self pointer: %v", err)
	}

	// Offset 12: label "a" then a pointer to 17; offset 17: pointer back
	// to 12. Following both would loop forever.
	pingPong := append(append([]byte(nil), header...), 1, 'a', 0xC0, 17, 0, 0xC0, 12)
	if _, _, err := ReadName(pingPong, 12); !errors.Is(err, ErrBadName) {
		t.Errorf("forward pointer: %v", err)
	}
	if _, _, err := ReadName(pingPong, 17); !errors.Is(err, ErrBadName) {
		t.Errorf("pointer loop: %v", err)
	}
}

func TestReadNameRejectsTruncation(t *testing.T) {
	msg := mustHex(t, cloaked)
	if _, _, err := ReadName(msg[:20], 12); !errors.Is(err, ErrShort) {
		t.Errorf("cut label: %v", err)
	}
	if _, _, err := ReadName(append(make([]byte, 12), 0xC0), 12); !errors.Is(err, ErrShort) {
		t.Errorf("cut pointer: %v", err)
	}
}

func TestCNAMETargetsNoCNAME(t *testing.T) {
	resp := buildQuery(1, "plain.example", TypeA)
	resp[2] |= 0x80
	resp = answerA(resp, 300, [4]byte{1, 2, 3, 4})
	got, err := CNAMETargets(resp)
	if err != nil || len(got) != 0 {
		t.Errorf("got %v, %v", got, err)
	}
}

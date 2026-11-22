package dnsmsg

import (
	"bytes"
	"testing"
)

func TestTruncate(t *testing.T) {
	query := buildQuery(0x7777, "big.example.com", TypeTXT)
	resp := bytes.Clone(query)
	resp[2] |= 0x80
	for range 50 {
		resp = answerA(resp, 300, [4]byte{1, 2, 3, 4})
	}

	small := Truncate(resp)
	if !Truncated(small) {
		t.Fatal("TC flag not set")
	}
	if be16(small, 0) != 0x7777 || small[2]&0x80 == 0 {
		t.Error("id or QR flag lost")
	}
	if !bytes.Equal(small[headerLen:], query[headerLen:]) {
		t.Error("question not kept")
	}
	if be16(small, 4) != 1 || be16(small, 6) != 0 || be16(small, 8) != 0 || be16(small, 10) != 0 {
		t.Errorf("counts = % x", small[4:12])
	}
	// The result must still be a valid response.
	if r, err := ParseResponse(small); err != nil || len(r.Records) != 0 || !r.Truncated {
		t.Errorf("parse: %+v, %v", r, err)
	}
}

func TestTruncateGarbage(t *testing.T) {
	junk := []byte{0, 1, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0, 9} // header, then a broken name
	out := Truncate(junk)
	if len(out) != headerLen || !Truncated(out) || be16(out, 4) != 0 {
		t.Errorf("out = % x", out)
	}
	if got := Truncate([]byte{1, 2}); len(got) != 2 {
		t.Error("short input should come back unchanged")
	}
}

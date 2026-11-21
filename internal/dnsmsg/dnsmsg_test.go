package dnsmsg
 
import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)
 
// buildQuery encodes a standard query with RD set, the way dig sends one.
func buildQuery(id uint16, name string, qtype uint16) []byte {
	b := binary.BigEndian.AppendUint16(nil, id)
	b = binary.BigEndian.AppendUint16(b, flagRD)
	b = binary.BigEndian.AppendUint16(b, 1) // qdcount
	b = append(b, 0, 0, 0, 0, 0, 0)         // an, ns, ar counts
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, 1) // class IN
	return b
}
 
func TestParse(t *testing.T) {
	q, err := Parse(buildQuery(0xBEEF, "Ads.Example.COM", TypeAAAA))
	if err != nil {
		t.Fatal(err)
	}
	if q.ID != 0xBEEF || q.Name != "ads.example.com" || q.Type != TypeAAAA || q.Class != 1 {
		t.Fatalf("got %+v", q)
	}
}
 
func TestBlockedA(t *testing.T) {
	query := buildQuery(0x1234, "ads.example.com", TypeA)
	q, _ := Parse(query)
	resp := q.Blocked()
 
	if id := be16(resp, 0); id != 0x1234 {
		t.Errorf("id = %#x", id)
	}
	flags := be16(resp, 2)
	if flags&flagQR == 0 || flags&flagRD == 0 || flags&flagRA == 0 || flags&0xF != RcodeSuccess {
		t.Errorf("flags = %016b", flags)
	}
	if qd, an := be16(resp, 4), be16(resp, 6); qd != 1 || an != 1 {
		t.Errorf("qdcount=%d ancount=%d", qd, an)
	}
	// Question echoed byte for byte.
	if !bytes.Equal(resp[headerLen:q.qEnd], query[headerLen:]) {
		t.Error("question not echoed")
	}
	// Answer: pointer, type, class, ttl, rdlength, 0.0.0.0
	ans := resp[q.qEnd:]
	want := []byte{0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, BlockedTTL, 0, 4, 0, 0, 0, 0}
	if !bytes.Equal(ans, want) {
		t.Errorf("answer = % x\nwant     % x", ans, want)
	}
}
 
func TestBlockedAAAA(t *testing.T) {
	q, _ := Parse(buildQuery(1, "ads.example.com", TypeAAAA))
	resp := q.Blocked()
	if len(resp) != q.qEnd+12+16 {
		t.Fatalf("len = %d", len(resp))
	}
	if !bytes.Equal(resp[len(resp)-16:], make([]byte, 16)) {
		t.Error("rdata is not ::")
	}
}
 
func TestBlockedOtherTypeIsNoData(t *testing.T) {
	q, _ := Parse(buildQuery(1, "ads.example.com", TypeMX))
	resp := q.Blocked()
	if an := be16(resp, 6); an != 0 {
		t.Errorf("ancount = %d", an)
	}
	if len(resp) != q.qEnd {
		t.Errorf("len = %d, want header + question only", len(resp))
	}
}
 
func TestParseRejects(t *testing.T) {
	valid := buildQuery(1, "a.example", TypeA)
 
	response := bytes.Clone(valid)
	response[2] |= 0x80
 
	twoQuestions := bytes.Clone(valid)
	twoQuestions[5] = 2
 
	pointer := bytes.Clone(valid)
	pointer[headerLen] = 0xC0
 
	longName := buildQuery(1, strings.Repeat("abcdefghi.", 26)+"com", TypeA)
 
	cases := []struct {
		name string
		msg  []byte
		want error
	}{
		{"empty", nil, ErrShort},
		{"header only", valid[:headerLen], ErrShort},
		{"cut in label", valid[:headerLen+3], ErrShort},
		{"cut before type", valid[:len(valid)-4], ErrShort},
		{"response", response, ErrNotQuery},
		{"two questions", twoQuestions, ErrQuestionCount},
		{"compression pointer", pointer, ErrBadName},
		{"name over 255", longName, ErrBadName},
	}
	for _, c := range cases {
		if _, err := Parse(c.msg); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}
 
func TestErrorResponse(t *testing.T) {
	query := buildQuery(0x4242, "x.example", TypeA)
	resp := ErrorResponse(query, RcodeServFail)
	if len(resp) != headerLen || be16(resp, 0) != 0x4242 || be16(resp, 2)&0xF != RcodeServFail {
		t.Errorf("resp = % x", resp)
	}
 
	if ErrorResponse(query[:5], RcodeFormErr) != nil {
		t.Error("replied to a message without a full header")
	}
	response := bytes.Clone(query)
	response[2] |= 0x80
	if ErrorResponse(response, RcodeFormErr) != nil {
		t.Error("replied to a response")
	}
}
 
func TestTypeName(t *testing.T) {
	if TypeName(TypeAAAA) != "AAAA" || TypeName(99) != "TYPE99" {
		t.Error("unexpected type names")
	}
}
 
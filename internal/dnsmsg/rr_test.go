package dnsmsg
 
import (
	"encoding/binary"
	"errors"
	"testing"
)
 
// withEDNS appends an OPT record (root name, type 41, class = UDP size,
// TTL holds the extended flags) and bumps ARCOUNT.
func withEDNS(q []byte, udpSize uint16, do bool) []byte {
	q = append([]byte(nil), q...)
	q[11]++
	q = append(q, 0) // root name
	q = binary.BigEndian.AppendUint16(q, TypeOPT)
	q = binary.BigEndian.AppendUint16(q, udpSize)
	var ttl uint32
	if do {
		ttl = 0x8000
	}
	q = binary.BigEndian.AppendUint32(q, ttl)
	return binary.BigEndian.AppendUint16(q, 0) // no options
}
 
// answerA appends an A record whose name is a pointer to the question.
func answerA(resp []byte, ttl uint32, ip [4]byte) []byte {
	resp[7]++ // ancount
	resp = append(resp, 0xC0, 0x0C, 0, 1, 0, 1)
	resp = binary.BigEndian.AppendUint32(resp, ttl)
	resp = append(resp, 0, 4)
	return append(resp, ip[:]...)
}
 
func TestParseEDNS(t *testing.T) {
	q, err := Parse(withEDNS(buildQuery(1, "example.com", TypeA), 1232, true))
	if err != nil {
		t.Fatal(err)
	}
	if !q.EDNS || q.UDPSize != 1232 || !q.DO {
		t.Errorf("edns=%v size=%d do=%v", q.EDNS, q.UDPSize, q.DO)
	}
 
	plain, _ := Parse(buildQuery(1, "example.com", TypeA))
	if plain.EDNS || plain.UDPSize != MinUDPSize || plain.DO {
		t.Errorf("plain query: %+v", plain)
	}
 
	// An advertised size below 512 is treated as 512 (RFC 6891 6.2.5).
	tiny, _ := Parse(withEDNS(buildQuery(1, "example.com", TypeA), 100, false))
	if tiny.UDPSize != MinUDPSize {
		t.Errorf("tiny size = %d", tiny.UDPSize)
	}
}
 
func TestParseRejectsBrokenAdditional(t *testing.T) {
	msg := withEDNS(buildQuery(1, "example.com", TypeA), 1232, false)
	if _, err := Parse(msg[:len(msg)-3]); !errors.Is(err, ErrShort) {
		t.Errorf("err = %v", err)
	}
}
 
func TestParseResponse(t *testing.T) {
	resp := buildQuery(0xABCD, "example.com", TypeA)
	resp[2] |= 0x80
	resp = answerA(resp, 300, [4]byte{1, 2, 3, 4})
	resp = answerA(resp, 120, [4]byte{5, 6, 7, 8})
 
	r, err := ParseResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != 0xABCD || r.Rcode != RcodeSuccess || r.Truncated || len(r.Records) != 2 {
		t.Fatalf("got %+v", r)
	}
	first := r.Records[0]
	if first.Section != SectionAnswer || first.Type != TypeA || first.TTL != 300 {
		t.Errorf("first = %+v", first)
	}
	if string(first.RData) != "\x01\x02\x03\x04" {
		t.Errorf("rdata = % x", first.RData)
	}
	// TTLOff must point at the TTL bytes so the cache can rewrite them.
	if got := binary.BigEndian.Uint32(resp[r.Records[1].TTLOff:]); got != 120 {
		t.Errorf("ttl at offset = %d", got)
	}
}
 
func TestParseResponseRejects(t *testing.T) {
	query := buildQuery(1, "example.com", TypeA)
	if _, err := ParseResponse(query); !errors.Is(err, ErrNotResponse) {
		t.Errorf("query: err = %v", err)
	}
 
	resp := append([]byte(nil), query...)
	resp[2] |= 0x80
	resp = answerA(resp, 60, [4]byte{})
	if _, err := ParseResponse(resp[:len(resp)-2]); !errors.Is(err, ErrShort) {
		t.Errorf("cut rdata: err = %v", err)
	}
 
	resp[7] = 2 // claims a second answer that is not there
	if _, err := ParseResponse(resp); !errors.Is(err, ErrShort) {
		t.Errorf("missing record: err = %v", err)
	}
}
 
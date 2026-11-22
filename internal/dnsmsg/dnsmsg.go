// Package dnsmsg parses DNS queries and builds the few responses a sinkhole
// needs. It follows RFC 1035 section 4 (message format).
//
// Wire layout of a message:
//
//	+---------------------+
//	| Header (12 bytes)   |  ID, flags, 4 section counts
//	+---------------------+
//	| Question            |  name, type, class
//	+---------------------+
//	| Answer              |  resource records
//	| Authority           |
//	| Additional          |
//	+---------------------+
package dnsmsg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const headerLen = 12

// Record types.
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeSRV   uint16 = 33
	TypeOPT   uint16 = 41 // EDNS pseudo record (RFC 6891)
	TypeHTTPS uint16 = 65
)

// Response codes (RCODE, low 4 bits of the flags).
const (
	RcodeSuccess  = 0
	RcodeFormErr  = 1
	RcodeServFail = 2
	RcodeNXDomain = 3
	RcodeRefused  = 5
)

// Bits inside the 16 bit flags field.
const (
	flagQR     uint16 = 1 << 15 // 1 = response, 0 = query
	opcodeMask uint16 = 0xF << 11
	flagTC     uint16 = 1 << 9 // truncated, client should retry over TCP
	flagRD     uint16 = 1 << 8 // recursion desired (copied from query)
	flagRA     uint16 = 1 << 7 // recursion available
	flagCD     uint16 = 1 << 4 // checking disabled (DNSSEC)
)

// MinUDPSize is the classic DNS limit for clients without EDNS.
const MinUDPSize = 512

// BlockedTTL is how long clients may cache a sinkholed answer, in seconds.
const BlockedTTL = 60

var (
	ErrShort         = errors.New("message truncated")
	ErrNotQuery      = errors.New("message is a response, not a query")
	ErrNotResponse   = errors.New("message is a query, not a response")
	ErrQuestionCount = errors.New("expected exactly one question")
	ErrBadName       = errors.New("malformed name")
)

// Query is a parsed DNS query with exactly one question.
type Query struct {
	ID    uint16
	Flags uint16
	Name  string // lowercase, no trailing dot, "" for the root
	Type  uint16
	Class uint16

	// From the EDNS OPT record, if the client sent one.
	EDNS    bool
	UDPSize int  // largest UDP reply the client accepts
	DO      bool // DNSSEC OK: client wants signatures
	CD      bool // checking disabled header flag

	raw  []byte // the original message
	qEnd int    // offset just past the question section
}

// Question returns the raw question section bytes.
func (q *Query) Question() []byte {
	return q.raw[headerLen:q.qEnd]
}

// Parse reads the header and the single question of a query.
func Parse(msg []byte) (*Query, error) {
	if len(msg) < headerLen {
		return nil, ErrShort
	}

	q := &Query{
		ID:    be16(msg, 0),
		Flags: be16(msg, 2),
	}
	if q.Flags&flagQR != 0 {
		return nil, ErrNotQuery
	}
	if be16(msg, 4) != 1 {
		return nil, ErrQuestionCount
	}

	name, off, err := readName(msg, headerLen)
	if err != nil {
		return nil, err
	}
	if off+4 > len(msg) {
		return nil, ErrShort
	}

	q.Name = name
	q.Type = be16(msg, off)
	q.Class = be16(msg, off+2)
	q.raw = msg
	q.qEnd = off + 4
	q.CD = q.Flags&flagCD != 0
	q.UDPSize = MinUDPSize

	// Queries usually carry one record: the EDNS OPT in the additional
	// section. Its class field is the client's UDP buffer size, and the
	// top bit of its extended flags (inside the TTL field) is DO.
	rrs, err := readRecords(msg, q.qEnd)
	if err != nil {
		return nil, err
	}
	for _, rr := range rrs {
		if rr.Section == SectionAdditional && rr.Type == TypeOPT {
			q.EDNS = true
			q.UDPSize = max(int(rr.Class), MinUDPSize)
			q.DO = rr.TTL&0x8000 != 0
		}
	}
	return q, nil
}

// readName decodes a sequence of length prefixed labels ending in a zero
// byte. Queries never need compression pointers in the question, so any
// pointer (top two bits set) is rejected instead of followed.
func readName(msg []byte, off int) (string, int, error) {
	var labels []string
	wireLen := 0

	for {
		if off >= len(msg) {
			return "", 0, ErrShort
		}
		l := int(msg[off])
		off++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 {
			return "", 0, ErrBadName
		}
		if off+l > len(msg) {
			return "", 0, ErrShort
		}
		// RFC 1035 2.3.4: a name is at most 255 bytes on the wire,
		// counting every length byte and the final zero.
		wireLen += 1 + l
		if wireLen+1 > 255 {
			return "", 0, ErrBadName
		}
		labels = append(labels, strings.ToLower(string(msg[off:off+l])))
		off += l
	}

	return strings.Join(labels, "."), off, nil
}

// Blocked builds the sinkhole answer: 0.0.0.0 for A, :: for AAAA, and an
// empty but successful answer (NODATA) for every other type.
func (q *Query) Blocked() []byte {
	var rdata []byte
	switch q.Type {
	case TypeA:
		rdata = make([]byte, 4)
	case TypeAAAA:
		rdata = make([]byte, 16)
	}

	ancount := uint16(0)
	if rdata != nil {
		ancount = 1
	}

	out := make([]byte, 0, q.qEnd+12+len(rdata))
	out = appendHeader(out, q.ID, responseFlags(q.Flags, RcodeSuccess), 1, ancount)
	out = append(out, q.raw[headerLen:q.qEnd]...) // echo the question

	if rdata != nil {
		out = append(out, 0xC0, headerLen) // pointer to the name in the question
		out = binary.BigEndian.AppendUint16(out, q.Type)
		out = binary.BigEndian.AppendUint16(out, q.Class)
		out = binary.BigEndian.AppendUint32(out, BlockedTTL)
		out = binary.BigEndian.AppendUint16(out, uint16(len(rdata)))
		out = append(out, rdata...)
	}
	return out
}

// ErrorResponse builds a header only reply with the given rcode. Returns nil
// when no reply should be sent: the input is too short to carry an ID, or
// it is itself a response (answering responses can cause loops).
func ErrorResponse(msg []byte, rcode int) []byte {
	if len(msg) < headerLen {
		return nil
	}
	flags := be16(msg, 2)
	if flags&flagQR != 0 {
		return nil
	}
	return appendHeader(nil, be16(msg, 0), responseFlags(flags, rcode), 0, 0)
}

// ResponseID returns the ID of a message, or false if it is too short.
func ResponseID(msg []byte) (uint16, bool) {
	if len(msg) < 2 {
		return 0, false
	}
	return be16(msg, 0), true
}

func responseFlags(queryFlags uint16, rcode int) uint16 {
	return flagQR | queryFlags&opcodeMask | queryFlags&flagRD | flagRA | uint16(rcode&0xF)
}

func appendHeader(b []byte, id, flags, qdcount, ancount uint16) []byte {
	b = binary.BigEndian.AppendUint16(b, id)
	b = binary.BigEndian.AppendUint16(b, flags)
	b = binary.BigEndian.AppendUint16(b, qdcount)
	b = binary.BigEndian.AppendUint16(b, ancount)
	b = binary.BigEndian.AppendUint16(b, 0) // nscount
	b = binary.BigEndian.AppendUint16(b, 0) // arcount
	return b
}

func be16(b []byte, off int) uint16 {
	return binary.BigEndian.Uint16(b[off:])
}

var typeNames = map[uint16]string{
	TypeA: "A", TypeNS: "NS", TypeCNAME: "CNAME", TypeSOA: "SOA",
	TypePTR: "PTR", TypeMX: "MX", TypeTXT: "TXT", TypeAAAA: "AAAA",
	TypeSRV: "SRV", TypeOPT: "OPT", TypeHTTPS: "HTTPS",
}

// TypeName returns a readable name like "AAAA", or "TYPE99" if unknown.
func TypeName(t uint16) string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("TYPE%d", t)
}

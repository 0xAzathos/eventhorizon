package dnsmsg

import "encoding/binary"

// Sections a resource record can live in.
const (
	SectionAnswer = iota
	SectionAuthority
	SectionAdditional
)

// RR is one resource record, pointing into the message it came from.
//
//	name | type (2) | class (2) | ttl (4) | rdlength (2) | rdata
type RR struct {
	Section int
	Type    uint16
	Class   uint16
	TTL     uint32
	TTLOff  int    // where the TTL sits in the message, for rewriting
	RData   []byte // slice of the original message
}

// skipName steps over a name without decoding it. Names in records may end
// in a compression pointer (two bytes, top bits 11) to a name earlier in
// the message; we never need to follow it, only to skip it.
func skipName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, ErrShort
		}
		l := msg[off]
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xC0 == 0xC0:
			if off+2 > len(msg) {
				return 0, ErrShort
			}
			return off + 2, nil
		case l&0xC0 != 0:
			return 0, ErrBadName // 01 and 10 prefixes are not in use
		default:
			off += 1 + int(l)
		}
	}
}

func readRR(msg []byte, off, section int) (RR, int, error) {
	off, err := skipName(msg, off)
	if err != nil {
		return RR{}, 0, err
	}
	if off+10 > len(msg) {
		return RR{}, 0, ErrShort
	}
	rdStart := off + 10
	rdEnd := rdStart + int(binary.BigEndian.Uint16(msg[off+8:]))
	if rdEnd > len(msg) {
		return RR{}, 0, ErrShort
	}
	return RR{
		Section: section,
		Type:    be16(msg, off),
		Class:   be16(msg, off+2),
		TTL:     binary.BigEndian.Uint32(msg[off+4:]),
		TTLOff:  off + 4,
		RData:   msg[rdStart:rdEnd],
	}, rdEnd, nil
}

// readRecords reads the answer, authority and additional sections, whose
// counts are in the header. off must point just past the question.
func readRecords(msg []byte, off int) ([]RR, error) {
	counts := [3]uint16{be16(msg, 6), be16(msg, 8), be16(msg, 10)}
	var rrs []RR
	for section, n := range counts {
		for range n {
			rr, next, err := readRR(msg, off, section)
			if err != nil {
				return nil, err
			}
			rrs = append(rrs, rr)
			off = next
		}
	}
	return rrs, nil
}

// Response is a parsed upstream reply.
type Response struct {
	ID          uint16
	Rcode       int
	Truncated   bool
	QuestionEnd int // offset just past the question section
	Records     []RR
}

// ParseResponse reads a reply with exactly one question.
func ParseResponse(msg []byte) (*Response, error) {
	if len(msg) < headerLen {
		return nil, ErrShort
	}
	flags := be16(msg, 2)
	if flags&flagQR == 0 {
		return nil, ErrNotResponse
	}
	if be16(msg, 4) != 1 {
		return nil, ErrQuestionCount
	}

	off, err := skipName(msg, headerLen)
	if err != nil {
		return nil, err
	}
	off += 4 // type and class
	if off > len(msg) {
		return nil, ErrShort
	}

	rrs, err := readRecords(msg, off)
	if err != nil {
		return nil, err
	}
	return &Response{
		ID:          be16(msg, 0),
		Rcode:       int(flags & 0xF),
		Truncated:   flags&flagTC != 0,
		QuestionEnd: off,
		Records:     rrs,
	}, nil
}
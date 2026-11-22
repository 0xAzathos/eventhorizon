package dnsmsg

import "strings"

// ReadName decodes the name at off, following compression pointers
// (RFC 1035 4.1.4): a two byte value with the top bits 11 that says "the
// rest of this name is at that earlier offset". It returns the name in
// lowercase without the trailing dot, and the offset just past the name
// where it started (a pointer counts as two bytes there).
//
// Messages come from the network, so every pointer must point strictly
// backwards from the one before it. That makes loops impossible: the
// position shrinks with every jump.
func ReadName(msg []byte, off int) (name string, next int, err error) {
	var labels []string
	wireLen := 0
	next = -1    // set at the first pointer, or at the end
	limit := off // a pointer must point before this

	for {
		if off >= len(msg) {
			return "", 0, ErrShort
		}
		l := int(msg[off])
		switch {
		case l == 0:
			if next < 0 {
				next = off + 1
			}
			return strings.Join(labels, "."), next, nil

		case l&0xC0 == 0xC0:
			if off+2 > len(msg) {
				return "", 0, ErrShort
			}
			target := int(be16(msg, off) & 0x3FFF)
			if target >= limit {
				return "", 0, ErrBadName // forward or self pointer: possible loop
			}
			if next < 0 {
				next = off + 2
			}
			off, limit = target, target

		case l&0xC0 != 0:
			return "", 0, ErrBadName

		default:
			if off+1+l > len(msg) {
				return "", 0, ErrShort
			}
			wireLen += 1 + l
			if wireLen+1 > 255 {
				return "", 0, ErrBadName
			}
			labels = append(labels, strings.ToLower(string(msg[off+1:off+1+l])))
			off += 1 + l
		}
	}
}

// CNAMETargets lists the names that CNAME records in the answer section
// point to, in order. For a cloaked tracker, "metrics.site.example" is
// answered with a CNAME to "site.tracker.example" plus that name's
// address; this returns ["site.tracker.example"].
func CNAMETargets(resp []byte) ([]string, error) {
	r, err := ParseResponse(resp)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range r.Records {
		if rr.Section != SectionAnswer || rr.Type != TypeCNAME {
			continue
		}
		target, _, err := ReadName(resp, rr.RDataOff)
		if err != nil {
			return nil, err
		}
		out = append(out, target)
	}
	return out, nil
}

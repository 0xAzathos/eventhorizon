package dnsmsg

import "bytes"

// Truncate turns a reply that is too big for the client's UDP buffer into
// the standard "please retry over TCP" answer: the header with the TC
// (truncated) flag set and the question, but no records (RFC 1035 4.1.1,
// RFC 7766 section 5).
//
// This matters when the upstream is reached over TCP or TLS: it then sends
// the full answer, however large, and a UDP client can only take what it
// advertised.
func Truncate(resp []byte) []byte {
	if len(resp) < headerLen {
		return resp
	}
	qEnd := headerLen
	qdcount := uint16(0)
	if r, err := ParseResponse(resp); err == nil {
		qEnd, qdcount = r.QuestionEnd, 1
	}
	out := bytes.Clone(resp[:qEnd])
	out[2] |= byte(flagTC >> 8)
	out[4], out[5] = byte(qdcount>>8), byte(qdcount)
	for i := 6; i < headerLen; i++ {
		out[i] = 0 // no answer, authority or additional records
	}
	return out
}

// Truncated reports whether the TC flag is set.
func Truncated(msg []byte) bool {
	return len(msg) >= 4 && be16(msg, 2)&flagTC != 0
}

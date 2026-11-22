package dnsmsg

import (
	"encoding/binary"
	"errors"
	"io"
)

// Over TCP every DNS message is preceded by its length as a 2 byte big
// endian number (RFC 1035 section 4.2.2), because TCP is a byte stream
// with no message boundaries of its own.

var ErrEmptyMessage = errors.New("zero length message")

// ReadFramed reads one length prefixed message.
func ReadFramed(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	if n == 0 {
		return nil, ErrEmptyMessage
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// WriteFramed sends the length prefix and message in a single write, so
// they leave in one segment instead of two.
func WriteFramed(w io.Writer, msg []byte) error {
	if len(msg) > 65535 {
		return errors.New("message too large for TCP framing")
	}
	out := make([]byte, 2, 2+len(msg))
	binary.BigEndian.PutUint16(out, uint16(len(msg)))
	out = append(out, msg...)
	_, err := w.Write(out)
	return err
}

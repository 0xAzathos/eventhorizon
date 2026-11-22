package dnsmsg

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestFraming(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFramed(&buf, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), []byte("\x00\x05hello")) {
		t.Errorf("framed = % x", buf.Bytes())
	}
	got, err := ReadFramed(&buf)
	if err != nil || string(got) != "hello" {
		t.Errorf("read back %q, %v", got, err)
	}
}

func TestFramingErrors(t *testing.T) {
	if _, err := ReadFramed(bytes.NewReader([]byte{0, 0})); !errors.Is(err, ErrEmptyMessage) {
		t.Errorf("zero length: err = %v", err)
	}
	if _, err := ReadFramed(bytes.NewReader([]byte{0, 9, 'a'})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("short body: err = %v", err)
	}
	if err := WriteFramed(io.Discard, make([]byte, 65536)); err == nil {
		t.Error("accepted a message too large for the length prefix")
	}
}

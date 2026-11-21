package server

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

// IdleTimeout closes TCP connections that send nothing for this long.
// RFC 7766 section 6.2.3 suggests a few seconds for a busy server.
const IdleTimeout = 10 * time.Second

var errEmptyMessage = errors.New("zero length message")

// ServeTCP accepts connections until ln is closed.
func (s *Server) ServeTCP(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.serveConn(conn)
	}
}

// serveConn answers queries on one connection, one after another. Clients
// may send several queries on the same connection (RFC 7766 section 6.2.1).
func (s *Server) serveConn(conn net.Conn) {
	defer conn.Close()
	for {
		if err := conn.SetDeadline(time.Now().Add(IdleTimeout)); err != nil {
			return
		}
		msg, err := readFramed(conn)
		if err != nil {
			// EOF is the normal way a client says goodbye.
			if !errors.Is(err, io.EOF) {
				s.Log.Debug("tcp read ended", "client", conn.RemoteAddr().String(), "err", err)
			}
			return
		}
		resp := s.respond(msg, conn.RemoteAddr(), "tcp")
		if resp == nil {
			return
		}
		if err := writeFramed(conn, resp); err != nil {
			return
		}
	}
}

// readFramed reads one message: a 2 byte big endian length, then that many
// bytes (RFC 1035 section 4.2.2).
func readFramed(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	if n == 0 {
		return nil, errEmptyMessage
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// writeFramed sends the length prefix and message in a single write, so
// they leave in one segment instead of two.
func writeFramed(w io.Writer, msg []byte) error {
	if len(msg) > 65535 {
		return errors.New("message too large for TCP framing")
	}
	out := make([]byte, 2, 2+len(msg))
	binary.BigEndian.PutUint16(out, uint16(len(msg)))
	out = append(out, msg...)
	_, err := w.Write(out)
	return err
}
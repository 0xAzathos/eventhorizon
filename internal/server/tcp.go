package server

import (
	"errors"
	"io"
	"net"
	"time"

	"eventhorizon/internal/dnsmsg"
)

// IdleTimeout closes TCP connections that send nothing for this long.
// RFC 7766 section 6.2.3 suggests a few seconds for a busy server.
const IdleTimeout = 10 * time.Second

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
		msg, err := dnsmsg.ReadFramed(conn)
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
		if err := dnsmsg.WriteFramed(conn, resp); err != nil {
			return
		}
	}
}

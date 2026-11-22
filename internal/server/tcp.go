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
		if !s.allowedClient(clientAddr(conn.RemoteAddr())) {
			conn.Close()
			continue
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
		var resp []byte
		if s.withinRate(clientAddr(conn.RemoteAddr())) {
			resp = s.respond(msg, conn.RemoteAddr(), "tcp")
		} else {
			// Over TCP the address is real, so saying no is safe.
			resp = dnsmsg.ErrorResponse(msg, dnsmsg.RcodeRefused)
		}
		if resp == nil {
			return
		}
		if err := dnsmsg.WriteFramed(conn, resp); err != nil {
			return
		}
	}
}

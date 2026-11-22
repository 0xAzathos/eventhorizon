package server

import (
	"errors"
	"net"
)

// ServeUDP handles packets until conn is closed. Each query gets its own
// goroutine, so one slow upstream answer never blocks the others.
func (s *Server) ServeUDP(conn net.PacketConn) error {
	buf := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		// Strangers and clients over their rate get silence (see guard.go).
		if ip := clientAddr(addr); !s.allowedClient(ip) || !s.withinRate(ip) {
			continue
		}
		// buf is reused by the next read, so hand the goroutine a copy.
		msg := append([]byte(nil), buf[:n]...)
		go func() {
			if resp := s.respond(msg, addr, "udp"); resp != nil {
				if _, err := conn.WriteTo(resp, addr); err != nil {
					s.Log.Warn("write failed", "client", addr.String(), "err", err)
				}
			}
		}()
	}
}

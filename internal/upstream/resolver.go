package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"
)

// Resolver looks names up through the pool's servers instead of the
// system resolver. eventhorizon needs this for its own downloads: once the
// machine's DNS points at eventhorizon, the system resolver leads back to
// eventhorizon itself, which is not answering yet while the blocklists
// load at startup.
//
// Every server is dialed over a stream, TLS for tls:// servers and TCP for
// plain ones, and Go's resolver speaks DNS over that stream. Over UDP a dead
// server would only show itself after the query was sent; over TCP the dial
// fails, so the next server in the pool's usual order gets its turn.
func (p *Pool) Resolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var errs []error
			for _, s := range p.order() {
				conn, err := s.dial(ctx, p.timeout)
				if err == nil {
					return conn, nil
				}
				errs = append(errs, err)
			}
			return nil, errors.Join(errs...)
		},
	}
}

func (s *server) dial(ctx context.Context, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	if s.tls == nil {
		return d.DialContext(ctx, "tcp", s.addr)
	}
	td := tls.Dialer{NetDialer: &d, Config: s.tls.Clone()}
	return td.DialContext(ctx, "tcp", s.addr)
}

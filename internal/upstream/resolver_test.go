package upstream

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/0xAzathos/eventhorizon/internal/dnsmsg"
)

// answerA answers A questions with ip and everything else with no data,
// the way a real server would, so Go's own resolver accepts the replies.
func answerA(ip [4]byte) func(q []byte) []byte {
	return func(q []byte) []byte {
		end := 12
		for q[end] != 0 {
			end += int(q[end]) + 1
		}
		end += 5 // root label, type, class
		qtype := binary.BigEndian.Uint16(q[end-4:])

		r := append([]byte(nil), q[:end]...)
		r[2], r[3] = 0x81, 0x80 // response, recursion desired and available
		binary.BigEndian.PutUint16(r[6:], 0)
		binary.BigEndian.PutUint16(r[8:], 0)
		binary.BigEndian.PutUint16(r[10:], 0)
		if qtype == 1 {
			binary.BigEndian.PutUint16(r[6:], 1)
			r = append(r, 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
			r = append(r, ip[:]...)
		}
		return r
	}
}

func TestResolverUsesThePoolNotTheSystem(t *testing.T) {
	f := newFake(t, answerA([4]byte{192, 0, 2, 7}))
	p := pool(t, 0, deadAddr(t), f.addr) // the first server refuses

	ips, err := p.Resolver().LookupNetIP(context.Background(), "ip4", "lists.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != netip.MustParseAddr("192.0.2.7") {
		t.Fatalf("got %v", ips)
	}
	if f.hits.Load() == 0 {
		t.Fatal("the pool's server was never asked")
	}
}

func TestResolverOverTLS(t *testing.T) {
	cert, roots := testCA(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	answer := answerA([4]byte{192, 0, 2, 8})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					q, err := dnsmsg.ReadFramed(c)
					if err != nil || dnsmsg.WriteFramed(c, answer(q)) != nil {
						return
					}
				}
			}()
		}
	}()

	p := tlsPool(t, roots, "tls://"+ln.Addr().String()+"#dns.test")
	ips, err := p.Resolver().LookupNetIP(context.Background(), "ip4", "lists.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != netip.MustParseAddr("192.0.2.8") {
		t.Fatalf("got %v", ips)
	}
}

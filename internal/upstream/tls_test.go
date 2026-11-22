package upstream

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0xAzathos/eventhorizon/internal/dnsmsg"
)

// testCA makes a throwaway certificate authority and a server certificate
// for "dns.test", so tests exercise real certificate verification.
func testCA(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "eventhorizon test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "dns.test"},
		DNSNames:     []string{"dns.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

type tlsFake struct {
	addr     string
	accepted atomic.Int32
	queries  atomic.Int32
}

// newTLSFake serves DNS over TLS. closeAfter > 0 makes it hang up after
// that many queries on a connection, like real servers do when idle.
func newTLSFake(t *testing.T, cert tls.Certificate, marker byte, closeAfter int) *tlsFake {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	f := &tlsFake{addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.accepted.Add(1)
			go func() {
				defer c.Close()
				for n := 1; ; n++ {
					q, err := dnsmsg.ReadFramed(c)
					if err != nil {
						return
					}
					f.queries.Add(1)
					if dnsmsg.WriteFramed(c, reply(q, 0, marker)) != nil {
						return
					}
					if closeAfter > 0 && n >= closeAfter {
						return
					}
				}
			}()
		}
	}()
	return f
}

// tlsPool builds a pool and trusts the test CA for every TLS server.
func tlsPool(t *testing.T, roots *x509.CertPool, specs ...string) *Pool {
	t.Helper()
	p := pool(t, time.Second, specs...)
	for _, s := range p.servers {
		if s.tls != nil {
			s.tls.RootCAs = roots
		}
	}
	t.Cleanup(p.Close)
	return p
}

func TestTLSExchange(t *testing.T) {
	cert, roots := testCA(t)
	f := newTLSFake(t, cert, 't', 0)
	p := tlsPool(t, roots, "tls://"+f.addr+"#dns.test")

	// A UDP client still gets its answer from a TLS upstream.
	r, err := p.Exchange("udp", query(1, "example.com"), 1)
	if err != nil || marker(r) != 't' {
		t.Fatalf("result %+v, err %v", r, err)
	}
	if st := p.Status()[0]; !st.Encrypted || !st.Up {
		t.Errorf("status %+v", st)
	}
}

func TestTLSReusesConnection(t *testing.T) {
	cert, roots := testCA(t)
	f := newTLSFake(t, cert, 't', 0)
	p := tlsPool(t, roots, "tls://"+f.addr+"#dns.test")

	for i := range 5 {
		if _, err := p.Exchange("udp", query(uint16(i), "example.com"), uint16(i)); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.accepted.Load(); n != 1 {
		t.Errorf("%d TLS handshakes for 5 queries, want 1", n)
	}
}

func TestTLSRecoversWhenServerClosesIdleConnection(t *testing.T) {
	cert, roots := testCA(t)
	f := newTLSFake(t, cert, 't', 1) // hangs up after every query
	p := tlsPool(t, roots, "tls://"+f.addr+"#dns.test")

	for i := range 3 {
		time.Sleep(20 * time.Millisecond) // let the hang up arrive
		r, err := p.Exchange("udp", query(uint16(i), "example.com"), uint16(i))
		if err != nil || marker(r) != 't' || r.Attempts != 1 {
			t.Fatalf("query %d: result %+v, err %v", i, r, err)
		}
	}
	if !p.Status()[0].Up {
		t.Error("a closed idle connection marked the server down")
	}
}

func TestTLSWrongCertificateNameFailsOver(t *testing.T) {
	cert, roots := testCA(t)
	f := newTLSFake(t, cert, 't', 0)
	backup := newFake(t, healthy('b'))
	p := tlsPool(t, roots, "tls://"+f.addr+"#evil.test", backup.addr)

	r, err := p.Exchange("udp", query(1, "example.com"), 1)
	if err != nil || marker(r) != 'b' {
		t.Fatalf("result %+v, err %v", r, err)
	}
	st := p.Status()[0]
	if st.Up || !strings.Contains(st.LastError, "certificate") {
		t.Errorf("status %+v, want down with a certificate error", st)
	}
	if f.queries.Load() != 0 {
		t.Error("a query was sent to a server with the wrong certificate")
	}
}

func TestTLSUntrustedCertificateFails(t *testing.T) {
	cert, _ := testCA(t)
	f := newTLSFake(t, cert, 't', 0)
	p := pool(t, time.Second, "tls://"+f.addr+"#dns.test") // system roots only

	if _, err := p.Exchange("udp", query(1, "example.com"), 1); err == nil {
		t.Error("accepted a certificate from an unknown authority")
	}
}

func TestParseSpec(t *testing.T) {
	cases := []struct {
		spec, addr, name string
		tls              bool
	}{
		{"1.1.1.1", "1.1.1.1:53", "", false},
		{"1.1.1.1:5353", "1.1.1.1:5353", "", false},
		{"tls://1.1.1.1#cloudflare-dns.com", "1.1.1.1:853", "cloudflare-dns.com", true},
		{"tls://9.9.9.9:8853#dns.quad9.net", "9.9.9.9:8853", "dns.quad9.net", true},
		{"tls://[2606:4700:4700::1111]#cloudflare-dns.com", "[2606:4700:4700::1111]:853", "cloudflare-dns.com", true},
		{"tls://1.1.1.1", "1.1.1.1:853", "1.1.1.1", true},
	}
	for _, c := range cases {
		s, err := parseSpec(c.spec)
		if err != nil {
			t.Errorf("%s: %v", c.spec, err)
			continue
		}
		if s.addr != c.addr || (s.tls != nil) != c.tls || (c.tls && s.tls.ServerName != c.name) {
			t.Errorf("%s: addr %s tls %v", c.spec, s.addr, s.tls)
		}
	}

	for _, bad := range []string{
		"dns.google:53",               // hostname would need DNS to resolve
		"tls://cloudflare-dns.com",    // same
		"1.1.1.1#cloudflare-dns.com",  // name without tls://
		"tls://1.1.1.1:notaport#x.io", // garbage port
	} {
		if _, err := parseSpec(bad); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
}

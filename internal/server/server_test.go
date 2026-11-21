package server
 
import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
 
	"sinkhole/internal/policy"
)
 
func query(id uint16, name string, qtype uint16) []byte {
	b := binary.BigEndian.AppendUint16(nil, id)
	b = append(b, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0) // RD, qdcount 1
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)
	return binary.BigEndian.AppendUint16(b, 1)
}
 
// listenBoth opens UDP and TCP on the same port, like a real DNS server.
func listenBoth(t *testing.T) (net.PacketConn, net.Listener) {
	t.Helper()
	for range 10 {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", pc.LocalAddr().String())
		if err != nil {
			pc.Close() // port busy on TCP, try another
			continue
		}
		t.Cleanup(func() { pc.Close(); ln.Close() })
		return pc, ln
	}
	t.Fatal("no free port for both UDP and TCP")
	return nil, nil
}
 
// upstreamHits counts queries per transport.
type upstreamHits struct{ udp, tcp atomic.Int32 }
 
// fakeUpstream echoes every query back with the QR bit set.
func fakeUpstream(t *testing.T) (string, *upstreamHits) {
	t.Helper()
	pc, ln := listenBoth(t)
	hits := new(upstreamHits)
 
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			hits.udp.Add(1)
			buf[2] |= 0x80
			pc.WriteTo(buf[:n], from)
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					msg, err := readFramed(c)
					if err != nil {
						return
					}
					hits.tcp.Add(1)
					msg[2] |= 0x80
					writeFramed(c, msg)
				}
			}()
		}
	}()
	return pc.LocalAddr().String(), hits
}
 
func startServer(t *testing.T, upstream string) string {
	t.Helper()
	block := policy.NewSet()
	block.Add("ads.example")
 
	srv := &Server{
		Policy:   &policy.Policy{Block: block},
		Upstream: upstream,
		Timeout:  300 * time.Millisecond,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	pc, ln := listenBoth(t)
	go srv.ServeUDP(pc)
	go srv.ServeTCP(ln)
	return pc.LocalAddr().String()
}
 
func exchangeUDP(t *testing.T, server string, msg []byte) []byte {
	t.Helper()
	c, err := net.Dial("udp", server)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}
 
func dialTCP(t *testing.T, server string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(2 * time.Second))
	return c
}
 
func exchangeTCP(t *testing.T, c net.Conn, msg []byte) []byte {
	t.Helper()
	if err := writeFramed(c, msg); err != nil {
		t.Fatal(err)
	}
	resp, err := readFramed(c)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
 
func isBlockedA(resp []byte) bool {
	return binary.BigEndian.Uint16(resp[6:]) == 1 &&
		bytes.Equal(resp[len(resp)-4:], []byte{0, 0, 0, 0})
}
 
func TestUDPBlockedNeverReachesUpstream(t *testing.T) {
	up, hits := fakeUpstream(t)
	srv := startServer(t, up)
 
	resp := exchangeUDP(t, srv, query(7, "x.ads.example", 1))
	if binary.BigEndian.Uint16(resp) != 7 || !isBlockedA(resp) {
		t.Errorf("not a blocked answer: % x", resp)
	}
	if hits.udp.Load()+hits.tcp.Load() != 0 {
		t.Error("blocked query was forwarded")
	}
}
 
func TestUDPAllowedIsForwarded(t *testing.T) {
	up, hits := fakeUpstream(t)
	srv := startServer(t, up)
 
	q := query(8, "good.example", 1)
	resp := exchangeUDP(t, srv, q)
	if hits.udp.Load() != 1 || hits.tcp.Load() != 0 {
		t.Fatalf("upstream udp=%d tcp=%d", hits.udp.Load(), hits.tcp.Load())
	}
	q[2] |= 0x80
	if !bytes.Equal(resp, q) {
		t.Errorf("relayed reply differs:\n% x\n% x", resp, q)
	}
}
 
func TestTCPForwardsOverTCP(t *testing.T) {
	up, hits := fakeUpstream(t)
	srv := startServer(t, up)
 
	resp := exchangeTCP(t, dialTCP(t, srv), query(11, "good.example", 1))
	if hits.tcp.Load() != 1 || hits.udp.Load() != 0 {
		t.Fatalf("upstream udp=%d tcp=%d, want tcp only", hits.udp.Load(), hits.tcp.Load())
	}
	if binary.BigEndian.Uint16(resp) != 11 || resp[2]&0x80 == 0 {
		t.Errorf("bad reply: % x", resp)
	}
}
 
func TestTCPPipelinedQueries(t *testing.T) {
	up, _ := fakeUpstream(t)
	srv := startServer(t, up)
	c := dialTCP(t, srv)
 
	// Several queries on one connection, mixing blocked and allowed.
	if resp := exchangeTCP(t, c, query(1, "ads.example", 1)); !isBlockedA(resp) {
		t.Error("first query not blocked")
	}
	if resp := exchangeTCP(t, c, query(2, "good.example", 1)); binary.BigEndian.Uint16(resp) != 2 {
		t.Error("second query wrong id")
	}
	if resp := exchangeTCP(t, c, query(3, "y.ads.example", 1)); !isBlockedA(resp) {
		t.Error("third query not blocked")
	}
}
 
func TestUpstreamDownGivesServFail(t *testing.T) {
	// Grab a free port, then close it so nothing answers there.
	pc, ln := listenBoth(t)
	dead := pc.LocalAddr().String()
	pc.Close()
	ln.Close()
 
	srv := startServer(t, dead)
	for _, resp := range [][]byte{
		exchangeUDP(t, srv, query(9, "good.example", 1)),
		exchangeTCP(t, dialTCP(t, srv), query(9, "good.example", 1)),
	} {
		if rcode := resp[3] & 0x0F; rcode != 2 {
			t.Errorf("rcode = %d, want SERVFAIL", rcode)
		}
	}
}
 
func TestMalformedGivesFormErr(t *testing.T) {
	up, _ := fakeUpstream(t)
	srv := startServer(t, up)
 
	bad := query(10, "good.example", 1)
	bad[5] = 2 // claim two questions
	if rcode := exchangeUDP(t, srv, bad)[3] & 0x0F; rcode != 1 {
		t.Errorf("rcode = %d, want FORMERR", rcode)
	}
}
 
func TestFraming(t *testing.T) {
	var buf bytes.Buffer
	writeFramed(&buf, []byte("hello"))
	if !bytes.Equal(buf.Bytes(), []byte("\x00\x05hello")) {
		t.Errorf("framed = % x", buf.Bytes())
	}
	got, err := readFramed(&buf)
	if err != nil || string(got) != "hello" {
		t.Errorf("read back %q, %v", got, err)
	}
 
	if _, err := readFramed(bytes.NewReader([]byte{0, 0})); !errors.Is(err, errEmptyMessage) {
		t.Errorf("zero length: err = %v", err)
	}
	if _, err := readFramed(bytes.NewReader([]byte{0, 9, 'a'})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("short body: err = %v", err)
	}
}
 
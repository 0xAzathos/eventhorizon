package server

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"eventhorizon/internal/cache"
	"eventhorizon/internal/detect"
	"eventhorizon/internal/dnsmsg"
	"eventhorizon/internal/events"
	"eventhorizon/internal/guard"
	"eventhorizon/internal/policy"
	"eventhorizon/internal/psl"
	"eventhorizon/internal/stats"
	"eventhorizon/internal/upstream"
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

// newPool wraps one fake upstream address in a failover pool.
func newPool(t *testing.T, addr string) *upstream.Pool {
	t.Helper()
	p, err := upstream.New([]string{addr}, 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	return p
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

// fakeAnswer turns a query into a reply: QR set, plus one A record
// (1.2.3.4, TTL 300) pointing back at the question name.
func fakeAnswer(q []byte) []byte {
	r := append([]byte(nil), q...)
	r[2] |= 0x80
	r[7]++ // ancount
	r = append(r, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0x01, 0x2C, 0, 4, 1, 2, 3, 4)
	return r
}

// nxAnswer turns a query into an NXDOMAIN reply.
func nxAnswer(q []byte) []byte {
	r := append([]byte(nil), q...)
	r[2] |= 0x80
	r[3] = 0x80 | 3
	return r
}

// fakeUpstream answers every query with fakeAnswer.
func fakeUpstream(t *testing.T) (string, *upstreamHits) {
	t.Helper()
	return fakeUpstreamWith(t, fakeAnswer)
}

// fakeUpstreamWith answers every query with answer(query), on UDP and TCP.
func fakeUpstreamWith(t *testing.T, answer func([]byte) []byte) (string, *upstreamHits) {
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
			pc.WriteTo(answer(buf[:n]), from)
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
					msg, err := dnsmsg.ReadFramed(c)
					if err != nil {
						return
					}
					hits.tcp.Add(1)
					dnsmsg.WriteFramed(c, answer(msg))
				}
			}()
		}
	}()
	return pc.LocalAddr().String(), hits
}

func startServer(t *testing.T, upstreamAddr string) string {
	t.Helper()
	return startServerWithCache(t, upstreamAddr, nil)
}

func startServerWithCache(t *testing.T, upstreamAddr string, c *cache.Cache) string {
	t.Helper()
	block := policy.NewSet()
	block.Add("ads.example")

	srv := &Server{
		Cache:    c,
		Upstream: newPool(t, upstreamAddr),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	srv.SetPolicy(&policy.Policy{Block: block})
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
	if err := dnsmsg.WriteFramed(c, msg); err != nil {
		t.Fatal(err)
	}
	resp, err := dnsmsg.ReadFramed(c)
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
	if want := fakeAnswer(q); !bytes.Equal(resp, want) {
		t.Errorf("relayed reply differs:\n% x\n% x", resp, want)
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

func TestCacheAnswersRepeats(t *testing.T) {
	up, hits := fakeUpstream(t)
	srv := startServerWithCache(t, up, cache.New(100, time.Hour))

	first := exchangeUDP(t, srv, query(20, "good.example", 1))
	second := exchangeUDP(t, srv, query(21, "good.example", 1))
	viaTCP := exchangeTCP(t, dialTCP(t, srv), query(22, "good.example", 1))

	if n := hits.udp.Load() + hits.tcp.Load(); n != 1 {
		t.Fatalf("upstream hits = %d, want 1", n)
	}
	for i, resp := range [][]byte{first, second, viaTCP} {
		if id := binary.BigEndian.Uint16(resp); id != uint16(20+i) {
			t.Errorf("reply %d has id %d", i, id)
		}
		if !bytes.Equal(resp[len(resp)-4:], []byte{1, 2, 3, 4}) {
			t.Errorf("reply %d lost the answer", i)
		}
	}
}

func TestPolicySwap(t *testing.T) {
	up, _ := fakeUpstream(t)
	block := policy.NewSet()
	srv := &Server{
		Upstream: newPool(t, up),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	srv.SetPolicy(&policy.Policy{Block: block})
	pc, ln := listenBoth(t)
	go srv.ServeUDP(pc)
	go srv.ServeTCP(ln)
	addr := pc.LocalAddr().String()

	if isBlockedA(exchangeUDP(t, addr, query(1, "new.example", 1))) {
		t.Fatal("blocked before the swap")
	}
	next := policy.NewSet()
	next.Add("new.example")
	srv.SetPolicy(&policy.Policy{Block: next})
	if !isBlockedA(exchangeUDP(t, addr, query(2, "new.example", 1))) {
		t.Error("not blocked after the swap")
	}
}

func TestParseQueryLog(t *testing.T) {
	for in, want := range map[string]QueryLog{"all": LogAll, "blocked": LogBlocked, "none": LogNone} {
		if got, err := ParseQueryLog(in); err != nil || got != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	if _, err := ParseQueryLog("loud"); err == nil {
		t.Error("accepted an unknown mode")
	}
}

// syncBuffer lets the server goroutines and the test share a log buffer.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestDGABurstRaisesAlert(t *testing.T) {
	up, _ := fakeUpstreamWith(t, nxAnswer)
	model, err := detect.DefaultModel()
	if err != nil {
		t.Fatal(err)
	}
	logs := new(syncBuffer)
	srv := &Server{
		Detect:   detect.New(detect.DefaultConfig(), model, nil, psl.Default),
		Upstream: newPool(t, up),
		Log:      slog.New(slog.NewTextHandler(logs, nil)),
		QueryLog: LogBlocked,
	}
	srv.SetPolicy(&policy.Policy{Block: policy.NewSet()})
	pc, ln := listenBoth(t)
	go srv.ServeUDP(pc)
	go srv.ServeTCP(ln)
	addr := pc.LocalAddr().String()

	// A normal name that does not exist: logged nowhere, no alert.
	exchangeUDP(t, addr, query(1, "typo.example", 1))

	for i, l := range []string{"xkq7v9zpl3wn", "qwzxjkvbnmpl", "zzkqxvbjwpfm", "pqxzvkjwbmtl", "jvqxzkwpbmfr"} {
		exchangeUDP(t, addr, query(uint16(10+i), l+".com", 1))
	}

	out := logs.String()
	if !strings.Contains(out, `msg="threat detected" kind=dga client=127.0.0.1`) {
		t.Errorf("no DGA alert in log:\n%s", out)
	}
	if strings.Contains(out, "typo.example") {
		t.Error("an ordinary query was logged in blocked mode")
	}
	if n := strings.Count(out, "suspicious=dga"); n != 5 {
		t.Errorf("%d suspicious query lines, want 5", n)
	}
}

func TestFeedsDashboard(t *testing.T) {
	up, _ := fakeUpstream(t)
	hub := events.NewHub()
	st := stats.New(time.Now())
	feed, cancel := hub.Subscribe()
	defer cancel()

	block := policy.NewSet()
	block.Add("ads.example")
	srv := &Server{
		Events:   hub,
		Stats:    st,
		Upstream: newPool(t, up),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	srv.SetPolicy(&policy.Policy{Block: block})
	pc, ln := listenBoth(t)
	go srv.ServeUDP(pc)
	go srv.ServeTCP(ln)
	addr := pc.LocalAddr().String()

	exchangeUDP(t, addr, query(1, "x.ads.example", 1))
	exchangeUDP(t, addr, query(2, "www.good.example", 1))

	var got []events.Event
	for len(got) < 2 {
		select {
		case e := <-feed:
			got = append(got, e)
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d events published", len(got))
		}
	}
	if got[0].Name != "x.ads.example" || got[0].Action != "blocked" || got[0].Client != "127.0.0.1" {
		t.Errorf("first event %+v", got[0])
	}
	if got[1].Action != "allowed" || got[1].Type != "A" || got[1].Proto != "udp" {
		t.Errorf("second event %+v", got[1])
	}

	snap := st.Snapshot(time.Now(), 5)
	if snap.Totals.Queries != 2 || snap.Totals.Blocked != 1 {
		t.Errorf("totals %+v", snap.Totals)
	}
	if len(snap.TopDomains) != 2 || srv.BlocklistSize() != 1 {
		t.Errorf("top domains %+v, blocklist %d", snap.TopDomains, srv.BlocklistSize())
	}
}

// bigAnswer replies with 40 A records: about 700 bytes, more than the 512
// a UDP client without EDNS accepts.
func bigAnswer(q []byte) []byte {
	r := append([]byte(nil), q...)
	r[2] |= 0x80
	for range 40 {
		r[7]++
		r = append(r, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0x01, 0x2C, 0, 4, 1, 2, 3, 4)
	}
	return r
}

func TestOversizedAnswerIsTruncatedForUDP(t *testing.T) {
	up, _ := fakeUpstreamWith(t, bigAnswer)
	srv := startServer(t, up)

	resp := exchangeUDP(t, srv, query(30, "big.example", 1))
	if len(resp) > 512 || resp[2]&0x02 == 0 {
		t.Fatalf("UDP reply is %d bytes, TC=%v; want a truncated reply", len(resp), resp[2]&0x02 != 0)
	}
	if binary.BigEndian.Uint16(resp) != 30 || binary.BigEndian.Uint16(resp[6:]) != 0 {
		t.Errorf("truncated reply % x", resp[:12])
	}

	// The retry over TCP gets the whole answer.
	full := exchangeTCP(t, dialTCP(t, srv), query(31, "big.example", 1))
	if n := binary.BigEndian.Uint16(full[6:]); n != 40 || full[2]&0x02 != 0 {
		t.Errorf("TCP reply has %d answers, TC=%v", n, full[2]&0x02 != 0)
	}
}

// cloakedAnswer replies the way a cloaked tracker does: the asked name is
// a CNAME for edge.tracker.example, followed by that name's address.
func cloakedAnswer(q []byte) []byte {
	r := append([]byte(nil), q...)
	r[2] |= 0x80
	r[7] = 2 // two answers
	target := []byte("\x04edge\x07tracker\x07example\x00")
	r = append(r, 0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0x01, 0x2C, 0, byte(len(target)))
	targetOff := len(r)
	r = append(r, target...)
	r = append(r, 0xC0|byte(targetOff>>8), byte(targetOff), 0, 1, 0, 1, 0, 0, 0x01, 0x2C, 0, 4, 9, 9, 9, 9)
	return r
}

// cnameServer runs a server over cloakedAnswer with the given policy and
// returns its address, the server and a live event feed.
func cnameServer(t *testing.T, pol *policy.Policy, c *cache.Cache) (string, *Server, <-chan events.Event) {
	t.Helper()
	up, _ := fakeUpstreamWith(t, cloakedAnswer)
	hub := events.NewHub()
	feed, cancel := hub.Subscribe()
	t.Cleanup(cancel)
	srv := &Server{
		Cache:    c,
		Events:   hub,
		Upstream: newPool(t, up),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	srv.SetPolicy(pol)
	pc, ln := listenBoth(t)
	go srv.ServeUDP(pc)
	go srv.ServeTCP(ln)
	return pc.LocalAddr().String(), srv, feed
}

func nextEvent(t *testing.T, feed <-chan events.Event) events.Event {
	t.Helper()
	select {
	case e := <-feed:
		return e
	case <-time.After(2 * time.Second):
		t.Fatal("no event")
		return events.Event{}
	}
}

func TestCNAMECloakedTrackerIsBlocked(t *testing.T) {
	block := policy.NewSet()
	block.Add("tracker.example")
	addr, _, feed := cnameServer(t, &policy.Policy{Block: block}, nil)

	resp := exchangeUDP(t, addr, query(40, "metrics.shop.example", 1))
	if !isBlockedA(resp) {
		t.Fatalf("cloaked tracker not sinkholed: % x", resp)
	}
	e := nextEvent(t, feed)
	if e.Action != "blocked" || e.Via != "edge.tracker.example" || e.Rule != "tracker.example" {
		t.Errorf("event %+v", e)
	}
}

func TestCNAMEAllowlistWins(t *testing.T) {
	block, allow := policy.NewSet(), policy.NewSet()
	block.Add("tracker.example")
	allow.Add("metrics.shop.example")
	addr, _, _ := cnameServer(t, &policy.Policy{Block: block, Allow: allow}, nil)

	resp := exchangeUDP(t, addr, query(41, "metrics.shop.example", 1))
	if isBlockedA(resp) || binary.BigEndian.Uint16(resp[6:]) != 2 {
		t.Errorf("allowlisted name was blocked through its CNAME: % x", resp)
	}
}

func TestCNAMECheckAppliesToCachedAnswers(t *testing.T) {
	addr, srv, _ := cnameServer(t, &policy.Policy{Block: policy.NewSet()}, cache.New(100, time.Hour))

	if resp := exchangeUDP(t, addr, query(42, "metrics.shop.example", 1)); isBlockedA(resp) {
		t.Fatal("blocked before any list mentions the tracker")
	}
	// A list reload adds the tracker; the cached answer must not slip past.
	block := policy.NewSet()
	block.Add("tracker.example")
	srv.SetPolicy(&policy.Policy{Block: block})
	if resp := exchangeUDP(t, addr, query(43, "metrics.shop.example", 1)); !isBlockedA(resp) {
		t.Error("cached answer bypassed the CNAME check")
	}
}

func TestCNAMEUnrelatedTargetPassesThrough(t *testing.T) {
	block := policy.NewSet()
	block.Add("ads.example")
	addr, _, _ := cnameServer(t, &policy.Policy{Block: block}, nil)

	resp := exchangeUDP(t, addr, query(44, "metrics.shop.example", 1))
	if isBlockedA(resp) || !bytes.Equal(resp[len(resp)-4:], []byte{9, 9, 9, 9}) {
		t.Errorf("unrelated CNAME changed the answer: % x", resp)
	}
}

// tryUDP sends one query and reports whether any reply came back.
func tryUDP(t *testing.T, server string, msg []byte) ([]byte, bool) {
	t.Helper()
	c, err := net.Dial("udp", server)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(300 * time.Millisecond))
	c.Write(msg)
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return nil, false
	}
	return buf[:n], true
}

func guardedServer(t *testing.T, acl *guard.ACL, lim *guard.Limiter) (string, *stats.Stats, *syncBuffer) {
	t.Helper()
	up, _ := fakeUpstream(t)
	st := stats.New(time.Now())
	logs := new(syncBuffer)
	srv := &Server{
		ACL:      acl,
		Limit:    lim,
		Stats:    st,
		Upstream: newPool(t, up),
		Log:      slog.New(slog.NewTextHandler(logs, nil)),
		QueryLog: LogNone,
	}
	srv.SetPolicy(&policy.Policy{Block: policy.NewSet()})
	pc, ln := listenBoth(t)
	go srv.ServeUDP(pc)
	go srv.ServeTCP(ln)
	return pc.LocalAddr().String(), st, logs
}

func TestStrangersGetSilenceOverUDP(t *testing.T) {
	acl, _ := guard.ParseACL("10.0.0.0/8") // the test client, 127.0.0.1, is not in it
	addr, st, logs := guardedServer(t, acl, nil)

	for i := range 3 {
		if resp, ok := tryUDP(t, addr, query(uint16(50+i), "good.example", 1)); ok {
			t.Fatalf("stranger got a reply: % x", resp)
		}
	}
	if n := st.Snapshot(time.Now(), 1).Totals.Refused; n != 3 {
		t.Errorf("refused = %d, want 3", n)
	}
	if n := strings.Count(logs.String(), "client turned away"); n != 1 {
		t.Errorf("logged %d times, want once per client", n)
	}
}

func TestStrangersAreDisconnectedOverTCP(t *testing.T) {
	acl, _ := guard.ParseACL("10.0.0.0/8")
	addr, _, _ := guardedServer(t, acl, nil)

	c := dialTCP(t, addr)
	dnsmsg.WriteFramed(c, query(60, "good.example", 1))
	if _, err := dnsmsg.ReadFramed(c); err == nil {
		t.Error("stranger got an answer over TCP")
	}
}

func TestAllowedClientsAreServed(t *testing.T) {
	acl, _ := guard.ParseACL("loopback,private")
	addr, st, _ := guardedServer(t, acl, nil)
	if _, ok := tryUDP(t, addr, query(61, "good.example", 1)); !ok {
		t.Fatal("allowed client got no reply")
	}
	if st.Snapshot(time.Now(), 1).Totals.Refused != 0 {
		t.Error("allowed client counted as refused")
	}
}

func TestRateLimit(t *testing.T) {
	addr, st, _ := guardedServer(t, nil, guard.NewLimiter(0.1, 3)) // bursts of 3, slow refill

	answered := 0
	for i := range 5 {
		if _, ok := tryUDP(t, addr, query(uint16(70+i), "good.example", 1)); ok {
			answered++
		}
	}
	if answered != 3 {
		t.Errorf("UDP: %d of 5 answered, want 3", answered)
	}

	// Over TCP the limited client hears REFUSED instead of silence.
	resp := exchangeTCP(t, dialTCP(t, addr), query(80, "good.example", 1))
	if rcode := resp[3] & 0x0F; rcode != dnsmsg.RcodeRefused {
		t.Errorf("TCP rcode = %d, want REFUSED", rcode)
	}
	if n := st.Snapshot(time.Now(), 1).Totals.Refused; n != 3 {
		t.Errorf("refused = %d, want 3", n)
	}
}

package upstream

import (
	"encoding/binary"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"eventhorizon/internal/dnsmsg"
)

func query(id uint16, name string) []byte {
	b := binary.BigEndian.AppendUint16(nil, id)
	b = append(b, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0, 0, 1, 0, 1)
}

// reply answers a query with the given rcode and one marker byte appended,
// so tests can tell which fake server answered.
func reply(q []byte, rcode byte, marker byte) []byte {
	r := append([]byte(nil), q...)
	r[2] |= 0x80
	r[3] = 0x80 | rcode
	return append(r, marker)
}

type fake struct {
	addr string
	hits atomic.Int32
}

// newFake serves UDP and TCP on one port. answer returns nil to stay
// silent, which looks like a timeout to the client.
func newFake(t *testing.T, answer func(q []byte) []byte) *fake {
	t.Helper()
	var pc net.PacketConn
	var ln net.Listener
	for range 10 {
		var err error
		pc, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		if ln, err = net.Listen("tcp", pc.LocalAddr().String()); err == nil {
			break
		}
		pc.Close()
	}
	t.Cleanup(func() { pc.Close(); ln.Close() })

	f := &fake{addr: pc.LocalAddr().String()}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			f.hits.Add(1)
			if r := answer(append([]byte(nil), buf[:n]...)); r != nil {
				pc.WriteTo(r, from)
			}
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
				q, err := dnsmsg.ReadFramed(c)
				if err != nil {
					return
				}
				f.hits.Add(1)
				if r := answer(q); r != nil {
					dnsmsg.WriteFramed(c, r)
				}
			}()
		}
	}()
	return f
}

func healthy(marker byte) func([]byte) []byte {
	return func(q []byte) []byte { return reply(q, 0, marker) }
}

func silent([]byte) []byte { return nil }

// deadAddr is a port where nothing listens: connections are refused.
func deadAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	return addr
}

func pool(t *testing.T, timeout time.Duration, addrs ...string) *Pool {
	t.Helper()
	p, err := New(addrs, timeout)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func marker(r Result) byte { return r.Resp[len(r.Resp)-1] }

func TestFirstHealthyServerAnswers(t *testing.T) {
	a, b := newFake(t, healthy('a')), newFake(t, healthy('b'))
	p := pool(t, time.Second, a.addr, b.addr)

	r, err := p.Exchange("udp", query(1, "example.com"), 1)
	if err != nil || marker(r) != 'a' || r.Attempts != 1 {
		t.Fatalf("result %+v, err %v", r, err)
	}
	if b.hits.Load() != 0 {
		t.Error("second server asked although the first was fine")
	}
}

func TestFailoverOnRefusedConnection(t *testing.T) {
	b := newFake(t, healthy('b'))
	p := pool(t, time.Second, deadAddr(t), b.addr)

	r, err := p.Exchange("udp", query(1, "example.com"), 1)
	if err != nil || marker(r) != 'b' || r.Attempts != 2 {
		t.Fatalf("result %+v, err %v", r, err)
	}
	if st := p.Status(); st[0].Up || st[0].LastError == "" || !st[1].Up {
		t.Errorf("status %+v", st)
	}

	// The dead server is now skipped: one attempt, straight to b.
	r, _ = p.Exchange("udp", query(2, "example.com"), 2)
	if r.Attempts != 1 || marker(r) != 'b' {
		t.Errorf("second query %+v", r)
	}
}

func TestTimeoutMarksDownSoLaterQueriesAreFast(t *testing.T) {
	a, b := newFake(t, silent), newFake(t, healthy('b'))
	p := pool(t, 150*time.Millisecond, a.addr, b.addr)

	if r, err := p.Exchange("udp", query(1, "example.com"), 1); err != nil || marker(r) != 'b' {
		t.Fatalf("result %+v, err %v", r, err)
	}

	start := time.Now()
	r, err := p.Exchange("udp", query(2, "example.com"), 2)
	if err != nil || marker(r) != 'b' {
		t.Fatalf("result %+v, err %v", r, err)
	}
	if took := time.Since(start); took > 100*time.Millisecond {
		t.Errorf("second query took %v: it waited for the silent server again", took)
	}
	if a.hits.Load() != 1 {
		t.Errorf("silent server asked %d times, want once", a.hits.Load())
	}
}

func TestDownServerIsRetriedAfterDownFor(t *testing.T) {
	var aUp atomic.Bool
	a := newFake(t, func(q []byte) []byte {
		if aUp.Load() {
			return reply(q, 0, 'a')
		}
		return nil
	})
	b := newFake(t, healthy('b'))
	p := pool(t, 150*time.Millisecond, a.addr, b.addr)
	clock := time.Now()
	p.now = func() time.Time { return clock }

	p.Exchange("udp", query(1, "example.com"), 1) // a times out, goes down
	aUp.Store(true)

	clock = clock.Add(DownFor - time.Second)
	if r, _ := p.Exchange("udp", query(2, "example.com"), 2); marker(r) != 'b' {
		t.Error("down server used before its time was up")
	}
	clock = clock.Add(2 * time.Second)
	if r, _ := p.Exchange("udp", query(3, "example.com"), 3); marker(r) != 'a' {
		t.Error("recovered server not preferred again")
	}
	if !p.Status()[0].Up {
		t.Error("recovered server still shown as down")
	}
}

func TestServfailMovesOnWithoutMarkingDown(t *testing.T) {
	a := newFake(t, func(q []byte) []byte { return reply(q, dnsmsg.RcodeServFail, 'a') })
	b := newFake(t, healthy('b'))
	p := pool(t, time.Second, a.addr, b.addr)

	r, err := p.Exchange("udp", query(1, "broken.example"), 1)
	if err != nil || marker(r) != 'b' {
		t.Fatalf("result %+v, err %v", r, err)
	}
	if !p.Status()[0].Up {
		t.Error("SERVFAIL marked the server down")
	}
}

func TestEveryoneServfailReturnsServfail(t *testing.T) {
	sf := func(m byte) func([]byte) []byte {
		return func(q []byte) []byte { return reply(q, dnsmsg.RcodeServFail, m) }
	}
	a, b := newFake(t, sf('a')), newFake(t, sf('b'))
	p := pool(t, time.Second, a.addr, b.addr)

	r, err := p.Exchange("udp", query(1, "broken.example"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if r.Resp[3]&0x0F != dnsmsg.RcodeServFail || marker(r) != 'a' || r.Attempts != 2 {
		t.Errorf("result %+v", r)
	}
}

func TestAllDownStillAsksEveryone(t *testing.T) {
	p := pool(t, time.Second, deadAddr(t), deadAddr(t))
	for range 2 { // second round: both are marked down, but still tried
		r, err := p.Exchange("udp", query(1, "example.com"), 1)
		if err == nil || r.Attempts != 2 {
			t.Errorf("result %+v, err %v", r, err)
		}
	}
}

func TestTCP(t *testing.T) {
	b := newFake(t, healthy('b'))
	p := pool(t, time.Second, deadAddr(t), b.addr)
	r, err := p.Exchange("tcp", query(7, "example.com"), 7)
	if err != nil || marker(r) != 'b' {
		t.Fatalf("result %+v, err %v", r, err)
	}
}

func TestIgnoresRepliesForOtherQueries(t *testing.T) {
	wrongID := newFake(t, func(q []byte) []byte {
		r := reply(q, 0, 'x')
		r[0] ^= 0xFF
		return r
	})
	b := newFake(t, healthy('b'))
	p := pool(t, 150*time.Millisecond, wrongID.addr, b.addr)
	if r, err := p.Exchange("udp", query(9, "example.com"), 9); err != nil || marker(r) != 'b' {
		t.Errorf("result %+v, err %v", r, err)
	}
}

func TestNewValidates(t *testing.T) {
	if _, err := New(nil, time.Second); err == nil {
		t.Error("accepted no servers")
	}
	if _, err := New([]string{"1.1.1.1"}, time.Second); err == nil {
		t.Error("accepted an address without a port")
	}
}

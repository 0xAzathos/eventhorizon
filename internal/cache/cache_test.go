package cache
 
import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
 
	"eventhorizon/internal/dnsmsg"
)
 
var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
 
func rawQuery(id uint16, name string, qtype uint16) []byte {
	b := binary.BigEndian.AppendUint16(nil, id)
	b = append(b, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)
	return binary.BigEndian.AppendUint16(b, 1)
}
 
func parse(t *testing.T, msg []byte) *dnsmsg.Query {
	t.Helper()
	q, err := dnsmsg.Parse(msg)
	if err != nil {
		t.Fatal(err)
	}
	return q
}
 
// reply turns a raw query into a NOERROR response with one A record per ttl.
func reply(query []byte, ttls ...uint32) []byte {
	r := bytes.Clone(query)
	r[2] |= 0x80
	r[3] |= 0x80 // RA
	for _, ttl := range ttls {
		r[7]++
		r = append(r, 0xC0, 0x0C, 0, 1, 0, 1)
		r = binary.BigEndian.AppendUint32(r, ttl)
		r = append(r, 0, 4, 93, 184, 216, 34)
	}
	return r
}
 
// nxdomain builds an NXDOMAIN reply with an SOA in the authority section.
func nxdomain(query []byte, soaTTL, minimum uint32) []byte {
	r := bytes.Clone(query)
	r[2] |= 0x80
	r[3] = 0x80 | dnsmsg.RcodeNXDomain
	r[9] = 1 // nscount
	r = append(r, 0xC0, 0x0C, 0, byte(dnsmsg.TypeSOA), 0, 1)
	r = binary.BigEndian.AppendUint32(r, soaTTL)
	rdata := []byte{0xC0, 0x0C, 0xC0, 0x0C} // mname, rname as pointers
	for _, v := range []uint32{2026010101, 7200, 3600, 1209600, minimum} {
		rdata = binary.BigEndian.AppendUint32(rdata, v)
	}
	r = binary.BigEndian.AppendUint16(r, uint16(len(rdata)))
	return append(r, rdata...)
}
 
func answerTTLs(t *testing.T, msg []byte) []uint32 {
	t.Helper()
	r, err := dnsmsg.ParseResponse(msg)
	if err != nil {
		t.Fatal(err)
	}
	var out []uint32
	for _, rr := range r.Records {
		out = append(out, rr.TTL)
	}
	return out
}
 
func TestHitRewritesIDAndCountsDownTTL(t *testing.T) {
	c := New(100, time.Hour)
	first := rawQuery(1, "example.com", dnsmsg.TypeA)
	if !c.Put(parse(t, first), reply(first, 300, 120), t0) {
		t.Fatal("not cached")
	}
 
	again := parse(t, rawQuery(2, "example.com", dnsmsg.TypeA))
	got, ok := c.Get(again, t0.Add(45*time.Second), 512)
	if !ok {
		t.Fatal("miss")
	}
	if id := binary.BigEndian.Uint16(got); id != 2 {
		t.Errorf("id = %d, want the new query's id", id)
	}
	ttls := answerTTLs(t, got)
	if ttls[0] != 255 || ttls[1] != 75 {
		t.Errorf("ttls = %v, want [255 75]", ttls)
	}
}
 
func TestExpiresAtSmallestTTL(t *testing.T) {
	c := New(100, time.Hour)
	q := rawQuery(1, "example.com", dnsmsg.TypeA)
	c.Put(parse(t, q), reply(q, 300, 120), t0)
 
	if _, ok := c.Get(parse(t, q), t0.Add(119*time.Second), 512); !ok {
		t.Error("expired too early")
	}
	if _, ok := c.Get(parse(t, q), t0.Add(120*time.Second), 512); ok {
		t.Error("served after the smallest TTL ran out")
	}
	if c.Len() != 0 {
		t.Error("expired entry not removed")
	}
}
 
func TestMaxTTLCapsLifetime(t *testing.T) {
	c := New(100, time.Minute)
	q := rawQuery(1, "example.com", dnsmsg.TypeA)
	c.Put(parse(t, q), reply(q, 86400), t0)
	if _, ok := c.Get(parse(t, q), t0.Add(61*time.Second), 512); ok {
		t.Error("kept beyond maxTTL")
	}
}
 
func TestKeepsClientLetterCase(t *testing.T) {
	c := New(100, time.Hour)
	q := rawQuery(1, "example.com", dnsmsg.TypeA)
	c.Put(parse(t, q), reply(q, 300), t0)
 
	mixed := rawQuery(2, "ExAmPlE.CoM", dnsmsg.TypeA)
	got, ok := c.Get(parse(t, mixed), t0, 512)
	if !ok {
		t.Fatal("case should not matter for lookup")
	}
	if !bytes.Contains(got, []byte("ExAmPlE")) {
		t.Error("question case not copied from the new query")
	}
}
 
func TestNegativeCaching(t *testing.T) {
	c := New(100, time.Hour)
	q := rawQuery(1, "nope.example.com", dnsmsg.TypeA)
	// SOA TTL 3600 but MINIMUM 900: RFC 2308 says use the smaller.
	if !c.Put(parse(t, q), nxdomain(q, 3600, 900), t0) {
		t.Fatal("NXDOMAIN not cached")
	}
	got, ok := c.Get(parse(t, q), t0.Add(899*time.Second), 512)
	if !ok || got[3]&0x0F != dnsmsg.RcodeNXDomain {
		t.Fatal("NXDOMAIN not served from cache")
	}
	if _, ok := c.Get(parse(t, q), t0.Add(900*time.Second), 512); ok {
		t.Error("kept past SOA MINIMUM")
	}
}
 
func TestNotCached(t *testing.T) {
	c := New(100, time.Hour)
	q := rawQuery(1, "example.com", dnsmsg.TypeA)
 
	truncated := reply(q, 300)
	truncated[2] |= 0x02
	servfail := reply(q)
	servfail[3] |= dnsmsg.RcodeServFail
	nodataNoSOA := reply(q)
	other := reply(rawQuery(1, "other.com", dnsmsg.TypeA), 300)
 
	cases := map[string][]byte{
		"truncated":      truncated,
		"servfail":       servfail,
		"nodata, no SOA": nodataNoSOA,
		"zero ttl":       reply(q, 0),
		"wrong question": other,
		"not a response": q,
	}
	for name, resp := range cases {
		if c.Put(parse(t, q), resp, t0) {
			t.Errorf("%s: was cached", name)
		}
	}
}
 
func TestTooBigForClient(t *testing.T) {
	c := New(100, time.Hour)
	q := rawQuery(1, "example.com", dnsmsg.TypeA)
	ttls := make([]uint32, 40) // 40 records of 16 bytes: about 670 bytes
	for i := range ttls {
		ttls[i] = 300
	}
	big := reply(q, ttls...)
	if !c.Put(parse(t, q), big, t0) {
		t.Fatal("not cached")
	}
	if _, ok := c.Get(parse(t, q), t0, 512); ok {
		t.Error("served a reply larger than the client's UDP limit")
	}
	if _, ok := c.Get(parse(t, q), t0, 65535); !ok {
		t.Error("TCP sized client should get it")
	}
}
 
func TestLRUEviction(t *testing.T) {
	c := New(2, time.Hour)
	a := rawQuery(1, "a.com", dnsmsg.TypeA)
	b := rawQuery(1, "b.com", dnsmsg.TypeA)
	d := rawQuery(1, "d.com", dnsmsg.TypeA)
 
	c.Put(parse(t, a), reply(a, 300), t0)
	c.Put(parse(t, b), reply(b, 300), t0)
	c.Get(parse(t, a), t0, 512) // a is now most recently used
	c.Put(parse(t, d), reply(d, 300), t0)
 
	if _, ok := c.Get(parse(t, b), t0, 512); ok {
		t.Error("b should have been evicted")
	}
	for _, q := range [][]byte{a, d} {
		if _, ok := c.Get(parse(t, q), t0, 512); !ok {
			t.Error("a or d missing")
		}
	}
}
 
func TestTypeIsPartOfKey(t *testing.T) {
	c := New(100, time.Hour)
	q := rawQuery(1, "example.com", dnsmsg.TypeA)
	c.Put(parse(t, q), reply(q, 300), t0)
	if _, ok := c.Get(parse(t, rawQuery(1, "example.com", dnsmsg.TypeAAAA)), t0, 512); ok {
		t.Error("A answer served for AAAA")
	}
}
 
func TestNilCache(t *testing.T) {
	var c *Cache
	q := rawQuery(1, "example.com", dnsmsg.TypeA)
	if c.Put(parse(t, q), reply(q, 300), t0) || c.Len() != 0 {
		t.Error("nil cache stored something")
	}
	if _, ok := c.Get(parse(t, q), t0, 512); ok {
		t.Error("nil cache returned something")
	}
}
 
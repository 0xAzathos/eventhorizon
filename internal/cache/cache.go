// Package cache stores upstream replies and serves them again until their
// TTL runs out, counting TTLs down so clients see the true remaining time.
//
// Rules:
//   - Only NOERROR and NXDOMAIN replies are cached, and never truncated ones.
//   - Positive answers live for the smallest TTL in the reply.
//   - Negative answers (NXDOMAIN, or NOERROR with no answer) live for
//     min(SOA TTL, SOA MINIMUM), per RFC 2308 section 5. Without an SOA
//     they are not cached.
//   - When full, the least recently used entry is evicted.
//
// A nil *Cache is valid and caches nothing.
package cache
 
import (
	"bytes"
	"container/list"
	"encoding/binary"
	"sync"
	"time"
 
	"eventhorizon/internal/dnsmsg"
)
 
// Key identifies which replies are interchangeable. EDNS and the DNSSEC
// bits change what the upstream sends back, so they are part of the key.
type Key struct {
	Name  string
	Type  uint16
	Class uint16
	EDNS  bool
	DO    bool
	CD    bool
}
 
func KeyFor(q *dnsmsg.Query) Key {
	return Key{q.Name, q.Type, q.Class, q.EDNS, q.DO, q.CD}
}
 
type entry struct {
	key     Key
	msg     []byte
	ttlOffs []int    // where each record's TTL lives in msg (OPT excluded)
	ttls    []uint32 // the original TTL values at those offsets
	stored  time.Time
	expires time.Time
}
 
type Cache struct {
	mu      sync.Mutex
	max     int
	maxTTL  time.Duration
	lru     *list.List // front = most recently used; values are *entry
	entries map[Key]*list.Element
}
 
// New returns a cache holding at most maxEntries replies, none kept longer
// than maxTTL however long their records say.
func New(maxEntries int, maxTTL time.Duration) *Cache {
	return &Cache{
		max:     maxEntries,
		maxTTL:  maxTTL,
		lru:     list.New(),
		entries: make(map[Key]*list.Element),
	}
}
 
// Put stores resp as the answer to q. Returns whether it was cached.
func (c *Cache) Put(q *dnsmsg.Query, resp []byte, now time.Time) bool {
	if c == nil || c.max <= 0 {
		return false
	}
	r, err := dnsmsg.ParseResponse(resp)
	if err != nil || r.Truncated {
		return false
	}
	// The reply must be for this exact question, or rewriting it for the
	// next client would produce garbage.
	if !bytes.EqualFold(resp[12:r.QuestionEnd], q.Question()) {
		return false
	}
 
	ttl, ok := lifetime(r)
	if !ok || ttl == 0 {
		return false
	}
	life := min(time.Duration(ttl)*time.Second, c.maxTTL)
 
	e := &entry{
		key:     KeyFor(q),
		msg:     bytes.Clone(resp),
		stored:  now,
		expires: now.Add(life),
	}
	for _, rr := range r.Records {
		if rr.Type == dnsmsg.TypeOPT {
			continue // its "TTL" field holds EDNS flags, not a TTL
		}
		e.ttlOffs = append(e.ttlOffs, rr.TTLOff)
		e.ttls = append(e.ttls, rr.TTL)
	}
 
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[e.key]; ok {
		el.Value = e
		c.lru.MoveToFront(el)
		return true
	}
	c.entries[e.key] = c.lru.PushFront(e)
	for c.lru.Len() > c.max {
		oldest := c.lru.Back()
		c.lru.Remove(oldest)
		delete(c.entries, oldest.Value.(*entry).key)
	}
	return true
}
 
// Get returns a cached reply rewritten for q: q's ID, q's question bytes
// (keeping the client's letter case), and TTLs reduced by the time spent
// in the cache. maxSize is the largest reply the client can receive; a
// cached reply bigger than that is not served.
func (c *Cache) Get(q *dnsmsg.Query, now time.Time, maxSize int) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	key := KeyFor(q)
 
	c.mu.Lock()
	defer c.mu.Unlock()
 
	el, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	e := el.Value.(*entry)
	if !now.Before(e.expires) {
		c.lru.Remove(el)
		delete(c.entries, key)
		return nil, false
	}
	if len(e.msg) > maxSize {
		return nil, false
	}
	c.lru.MoveToFront(el)
 
	out := bytes.Clone(e.msg)
	binary.BigEndian.PutUint16(out, q.ID)
	copy(out[12:], q.Question())
 
	elapsed := uint32(now.Sub(e.stored) / time.Second)
	for i, off := range e.ttlOffs {
		remaining := uint32(0)
		if e.ttls[i] > elapsed {
			remaining = e.ttls[i] - elapsed
		}
		binary.BigEndian.PutUint32(out[off:], remaining)
	}
	return out, true
}
 
// Len reports how many replies are stored, expired ones included until
// they are next looked up.
func (c *Cache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}
 
// lifetime decides how long, in seconds, a reply may be cached.
func lifetime(r *dnsmsg.Response) (uint32, bool) {
	hasAnswer := false
	for _, rr := range r.Records {
		if rr.Section == dnsmsg.SectionAnswer {
			hasAnswer = true
			break
		}
	}
 
	switch {
	case r.Rcode == dnsmsg.RcodeSuccess && hasAnswer:
		return minTTL(r.Records), true
	case r.Rcode == dnsmsg.RcodeSuccess, r.Rcode == dnsmsg.RcodeNXDomain:
		return negativeTTL(r.Records)
	default:
		return 0, false
	}
}
 
func minTTL(rrs []dnsmsg.RR) uint32 {
	m := ^uint32(0)
	for _, rr := range rrs {
		if rr.Type != dnsmsg.TypeOPT && rr.TTL < m {
			m = rr.TTL
		}
	}
	return m
}
 
// negativeTTL implements RFC 2308 section 5: use the SOA record from the
// authority section, capped by its MINIMUM field. MINIMUM is the last of
// the five 32 bit numbers that end the SOA rdata.
func negativeTTL(rrs []dnsmsg.RR) (uint32, bool) {
	for _, rr := range rrs {
		if rr.Section == dnsmsg.SectionAuthority && rr.Type == dnsmsg.TypeSOA && len(rr.RData) >= 20 {
			minimum := binary.BigEndian.Uint32(rr.RData[len(rr.RData)-4:])
			return min(rr.TTL, minimum), true
		}
	}
	return 0, false
}
 
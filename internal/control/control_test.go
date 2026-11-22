package control

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/0xAzathos/eventhorizon/internal/policy"
	"github.com/0xAzathos/eventhorizon/internal/rules"
)

// recorder keeps the last policy the controller installed.
type recorder struct {
	mu sync.Mutex
	p  *policy.Policy
	n  int
}

func (r *recorder) apply(p *policy.Policy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.p, r.n = p, r.n+1
}

func (r *recorder) decide(name string) policy.Decision {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.p.Decide(name)
}

func newController(t *testing.T) (*Controller, *recorder, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.txt")
	store, err := rules.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	c := New(store, rec.apply)
	lists := policy.NewSet()
	lists.Add("tracker.example")
	c.SetLists(lists, nil)
	return c, rec, path
}

func TestRuleAppliesImmediately(t *testing.T) {
	c, rec, _ := newController(t)
	if !rec.decide("a.tracker.example").Blocked {
		t.Fatal("list not active")
	}
	if _, err := c.SetRule("a.tracker.example", rules.Allow); err != nil {
		t.Fatal(err)
	}
	if d := rec.decide("a.tracker.example"); d.Blocked || !d.Mine {
		t.Errorf("after allow: %+v", d)
	}
	if !rec.decide("b.tracker.example").Blocked {
		t.Error("allowing one subdomain unblocked its siblings")
	}
}

func TestRulesSurviveListReload(t *testing.T) {
	c, rec, _ := newController(t)
	c.SetRule("mine.example", rules.Block)

	fresh := policy.NewSet()
	fresh.Add("other.example")
	c.SetLists(fresh, nil)

	if !rec.decide("mine.example").Blocked {
		t.Error("user rule lost when the lists were reloaded")
	}
	if rec.decide("tracker.example").Blocked {
		t.Error("old list entry still active after reload")
	}
}

func TestRemoveRule(t *testing.T) {
	c, rec, _ := newController(t)
	c.SetRule("tracker.example", rules.Allow)
	if ok, err := c.RemoveRule("tracker.example"); !ok || err != nil {
		t.Fatalf("remove: %v %v", ok, err)
	}
	if !rec.decide("tracker.example").Blocked {
		t.Error("removing the allow rule did not restore the list block")
	}
	before := rec.n
	if ok, _ := c.RemoveRule("never.example"); ok || rec.n != before {
		t.Error("removing a missing rule changed the policy")
	}
}

func TestBadRuleChangesNothing(t *testing.T) {
	c, rec, _ := newController(t)
	before := rec.n
	if _, err := c.SetRule("not a domain", rules.Block); err == nil {
		t.Fatal("accepted a bad domain")
	}
	if rec.n != before || len(c.Rules()) != 0 {
		t.Error("a rejected rule still changed state")
	}
}

func TestReloadGoesThroughMainLoop(t *testing.T) {
	c, _, _ := newController(t)
	// Stand in for main's loop: answer one request.
	go func() {
		reply := <-c.Requests()
		reply <- errors.New("list host down")
	}()
	err := c.Reload(context.Background())
	if err == nil || err.Error() != "list host down" {
		t.Errorf("err = %v", err)
	}

	// Nobody serving the loop: Reload must give up when the context ends.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := c.Reload(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want deadline", err)
	}
}

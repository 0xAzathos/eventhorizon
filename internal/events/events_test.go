package events

import (
	"fmt"
	"testing"
	"time"
)

func q(name string) Event {
	return Event{Time: time.Now(), Kind: "query", Name: name}
}

func TestFanOut(t *testing.T) {
	h := NewHub()
	a, cancelA := h.Subscribe()
	b, cancelB := h.Subscribe()
	defer cancelA()
	defer cancelB()

	h.Publish(q("one.example"))
	for _, ch := range []<-chan Event{a, b} {
		select {
		case e := <-ch:
			if e.Name != "one.example" {
				t.Errorf("got %q", e.Name)
			}
		case <-time.After(time.Second):
			t.Fatal("event not delivered")
		}
	}
}

func TestBacklogOldestFirst(t *testing.T) {
	h := NewHub()
	for i := range BacklogSize + 50 {
		h.Publish(q(fmt.Sprintf("n%d", i)))
	}
	ch, cancel := h.Subscribe()
	defer cancel()

	for i := range BacklogSize {
		e := <-ch
		if want := fmt.Sprintf("n%d", 50+i); e.Name != want {
			t.Fatalf("backlog[%d] = %q, want %q", i, e.Name, want)
		}
	}
}

func TestSlowViewerNeverBlocksPublish(t *testing.T) {
	h := NewHub()
	_, cancel := h.Subscribe() // never read from
	defer cancel()

	done := make(chan struct{})
	go func() {
		for i := range 10 * subBuffer {
			h.Publish(q(fmt.Sprintf("n%d", i)))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a slow viewer")
	}
	if h.Dropped() == 0 {
		t.Error("expected dropped events to be counted")
	}
}

func TestCancelClosesAndIsIdempotent(t *testing.T) {
	h := NewHub()
	ch, cancel := h.Subscribe()
	cancel()
	cancel() // second call must not panic
	if _, open := <-ch; open {
		t.Error("channel still open after cancel")
	}
	h.Publish(q("after.example")) // must not send on the closed channel
}

func TestNilHub(t *testing.T) {
	var h *Hub
	h.Publish(q("x"))
	if h.Dropped() != 0 {
		t.Error("nil hub counted drops")
	}
}

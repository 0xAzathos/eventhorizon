// Package control owns the active policy: it combines the blocklists and
// allowlist file (rebuilt on reload) with the user's own rules (changed at
// any time), and installs the result. Rule changes take effect at once and
// never re-download the lists.
package control

import (
	"context"
	"sync"

	"github.com/0xAzathos/eventhorizon/internal/policy"
	"github.com/0xAzathos/eventhorizon/internal/rules"
)

type Controller struct {
	apply func(*policy.Policy) // installs a policy, e.g. server.SetPolicy
	rules *rules.Store

	mu        sync.Mutex
	lists     *policy.Set // from the last successful reload
	allowFile *policy.Set

	reloads chan chan error
}

func New(rulesStore *rules.Store, apply func(*policy.Policy)) *Controller {
	return &Controller{
		apply:   apply,
		rules:   rulesStore,
		reloads: make(chan chan error),
	}
}

// SetLists installs freshly built lists, keeping the user's rules.
func (c *Controller) SetLists(block, allowFile *policy.Set) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lists, c.allowFile = block, allowFile
	c.installLocked()
}

// installLocked builds a complete new policy and swaps it in as a whole.
func (c *Controller) installLocked() {
	userAllow, userBlock := c.rules.Sets()
	c.apply(&policy.Policy{
		Block:     c.lists,
		Allow:     c.allowFile,
		UserAllow: userAllow,
		UserBlock: userBlock,
	})
}

func (c *Controller) Rules() []rules.Rule {
	return c.rules.List()
}

// SetRule saves an allow or block rule and applies it immediately.
func (c *Controller) SetRule(domain, action string) (rules.Rule, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, err := c.rules.Set(domain, action)
	if err != nil {
		return r, err
	}
	c.installLocked()
	return r, nil
}

// RemoveRule deletes a rule and applies the change immediately.
func (c *Controller) RemoveRule(domain string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ok, err := c.rules.Remove(domain)
	if ok {
		c.installLocked()
	}
	return ok, err
}

// Reload asks the main loop to rebuild the lists and waits for the result.
// Going through the main loop means a reload from the API can never run
// at the same time as a scheduled one or one from SIGHUP.
func (c *Controller) Reload(ctx context.Context) error {
	reply := make(chan error, 1)
	select {
	case c.reloads <- reply:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-reply:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Requests is read by the main loop; each request carries the channel
// to send the reload's result to.
func (c *Controller) Requests() <-chan chan error {
	return c.reloads
}

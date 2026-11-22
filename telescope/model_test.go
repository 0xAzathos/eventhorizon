package main

import (
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"eventhorizon/internal/api"
	"eventhorizon/internal/apiclient"
	"eventhorizon/internal/control"
	"eventhorizon/internal/events"
	"eventhorizon/internal/policy"
	"eventhorizon/internal/rules"
	"eventhorizon/internal/stats"
)

// startAPI runs eventhorizon's real API and controller, so the commands
// telescope sends are exercised for real.
func startAPI(t *testing.T) (*apiclient.Client, *control.Controller) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h, err := api.New(ln.Addr().String(), stats.New(time.Now()), events.NewHub())
	if err != nil {
		t.Fatal(err)
	}
	store, err := rules.Open(filepath.Join(t.TempDir(), "rules.txt"))
	if err != nil {
		t.Fatal(err)
	}
	ctl := control.New(store, func(*policy.Policy) {})
	ctl.SetLists(policy.NewSet(), nil)
	h.Control = ctl
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return apiclient.New(ln.Addr().String()), ctl
}

func key(s string) tea.KeyPressMsg { return tea.KeyPressMsg{Text: s} }

// press sends keys and returns the model plus the last command.
func press(t *testing.T, m model, keys ...string) (model, tea.Cmd) {
	t.Helper()
	var cmd tea.Cmd
	for _, k := range keys {
		var next tea.Model
		next, cmd = m.Update(key(k))
		m = next.(model)
	}
	return m, cmd
}

func send(m model, msg tea.Msg) model {
	next, _ := m.Update(msg)
	return next.(model)
}

func withQueries(t *testing.T, names ...string) model {
	t.Helper()
	c, _ := startAPI(t)
	m := newModel(c, "test")
	m = send(m, tea.WindowSizeMsg{Width: 120, Height: 40})
	for _, n := range names {
		m = send(m, eventMsg(events.Event{Kind: "query", Name: n, Action: "blocked", Client: "10.0.0.2"}))
	}
	return m
}

func TestSelectFreezesTheLog(t *testing.T) {
	m := withQueries(t, "one.example", "two.example", "three.example")

	m, _ = press(t, m, "up")
	if m.mode != modeSelect {
		t.Fatal("up did not start selecting")
	}
	if e, _ := m.selected(); e.Name != "three.example" {
		t.Errorf("first selection = %q, want the newest", e.Name)
	}
	m, _ = press(t, m, "down", "j")
	if e, _ := m.selected(); e.Name != "one.example" {
		t.Errorf("after two downs = %q", e.Name)
	}
	m, _ = press(t, m, "down") // already at the bottom
	if m.cursor != 2 {
		t.Errorf("cursor ran past the end: %d", m.cursor)
	}

	// New traffic must not move the selected line.
	m = send(m, eventMsg(events.Event{Kind: "query", Name: "four.example"}))
	if e, _ := m.selected(); e.Name != "one.example" || len(m.shown()) != 3 {
		t.Errorf("selection moved under new traffic: %q, %d shown", e.Name, len(m.shown()))
	}

	m, _ = press(t, m, "esc")
	if m.mode != modeLive || len(m.shown()) != 4 {
		t.Errorf("esc: mode %v, %d shown", m.mode, len(m.shown()))
	}
}

func TestSearch(t *testing.T) {
	m := withQueries(t, "github.com", "doubleclick.net", "api.github.com")

	m, _ = press(t, m, "/", "G", "i", "t")
	if !m.typing || m.search != "git" {
		t.Fatalf("typing=%v search=%q", m.typing, m.search)
	}
	if n := len(m.shown()); n != 2 {
		t.Errorf("search matched %d, want 2", n)
	}
	m, _ = press(t, m, "backspace", "enter")
	if m.typing || m.search != "gi" {
		t.Errorf("after backspace and enter: typing=%v search=%q", m.typing, m.search)
	}
	// Keys work normally again once typing is done.
	m, _ = press(t, m, "?")
	if m.mode != modeHelp {
		t.Error("? did not open help after the search")
	}
	m, _ = press(t, m, "x", "esc")
	if m.search != "" {
		t.Errorf("esc did not clear the search: %q", m.search)
	}
}

func TestTypingDoesNotTriggerKeys(t *testing.T) {
	m := withQueries(t, "a.example")
	m, cmd := press(t, m, "/", "q", "r", "b")
	if m.search != "qrb" || m.mode != modeLive || m.reloading || cmd != nil {
		t.Errorf("keys leaked out of the search box: search=%q reloading=%v", m.search, m.reloading)
	}
}

func TestAllowSelectedDomain(t *testing.T) {
	m := withQueries(t, "img.cdn.example.co.uk")

	m, cmd := press(t, m, "up", "A") // whole domain
	if cmd == nil {
		t.Fatal("A gave no command")
	}
	msg, ok := cmd().(ruleSetMsg)
	if !ok || msg.err != nil {
		t.Fatalf("result %#v", msg)
	}
	if msg.rule.Domain != "example.co.uk" || msg.rule.Action != rules.Allow {
		t.Errorf("rule %+v, want allow example.co.uk", msg.rule)
	}
	m = send(m, msg)
	if m.status == "" || m.statusBad {
		t.Errorf("status %q bad=%v", m.status, m.statusBad)
	}

	_, cmd = press(t, m, "b") // exact name
	if msg := cmd().(ruleSetMsg); msg.rule.Domain != "img.cdn.example.co.uk" || msg.rule.Action != rules.Block {
		t.Errorf("rule %+v, want block of the exact name", msg.rule)
	}
}

func TestRuleKeysNeedASelection(t *testing.T) {
	m := withQueries(t, "a.example")
	m, _ = press(t, m, "b")
	if !m.statusBad {
		t.Error("b without a selection should explain what to do")
	}
}

func TestRulesScreen(t *testing.T) {
	m := withQueries(t)
	c := m.client
	cmd := setRule(c, "one.example", rules.Block)
	cmd()
	cmd = setRule(c, "two.example", rules.Allow)
	cmd()

	m, cmd = press(t, m, "R")
	if m.mode != modeRules || cmd == nil {
		t.Fatal("R did not open the rules screen")
	}
	m = send(m, cmd())
	if len(m.rules) != 2 {
		t.Fatalf("rules %v", m.rules)
	}
	m, cmd = press(t, m, "down", "d")
	msg := cmd().(ruleRemovedMsg)
	if msg.err != nil || msg.domain != "two.example" {
		t.Errorf("removed %+v", msg)
	}
	m, _ = press(t, m, "esc")
	if m.mode != modeLive {
		t.Error("esc did not leave the rules screen")
	}
}

func TestHelpClosesOnAnyKey(t *testing.T) {
	m := withQueries(t)
	m, _ = press(t, m, "?")
	m, cmd := press(t, m, "q") // q closes help, it does not quit
	if m.mode != modeLive || cmd != nil {
		t.Error("help did not close cleanly")
	}
}

func TestReloadOnlyOnceAtATime(t *testing.T) {
	m := withQueries(t)
	m, first := press(t, m, "r")
	if !m.reloading || first == nil {
		t.Fatal("r did not start a reload")
	}
	if _, second := press(t, m, "r"); second != nil {
		t.Error("second r started another reload while one was running")
	}
	m = send(m, reloadDoneMsg{})
	if m.reloading {
		t.Error("still reloading after it finished")
	}
}

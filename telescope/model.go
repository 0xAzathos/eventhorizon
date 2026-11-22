package main

import (
	"context"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/0xAzathos/eventhorizon/internal/apiclient"
	"github.com/0xAzathos/eventhorizon/internal/dash"
	"github.com/0xAzathos/eventhorizon/internal/events"
	"github.com/0xAzathos/eventhorizon/internal/psl"
	"github.com/0xAzathos/eventhorizon/internal/rules"
	"github.com/0xAzathos/eventhorizon/internal/stats"
)

// Messages the program receives besides keys and window sizes.
type (
	snapshotMsg struct {
		snap stats.Snapshot
		err  error
	}
	eventMsg         events.Event
	streamRestartMsg struct{}
	tickMsg          time.Time

	ruleSetMsg struct {
		rule rules.Rule
		err  error
	}
	ruleRemovedMsg struct {
		domain string
		err    error
	}
	rulesMsg struct {
		rules []rules.Rule
		err   error
	}
	reloadDoneMsg  struct{ err error }
	clearStatusMsg struct{ id int }
)

const maxAlerts = 50

type mode int

const (
	modeLive   mode = iota
	modeSelect      // log frozen, a line selected
	modeRules       // the user's rules, full screen
	modeHelp        // key overview, full screen
)

type model struct {
	client *apiclient.Client
	addr   string

	width, height int

	snap     stats.Snapshot
	haveSnap bool
	live     bool   // last stats request succeeded
	lastErr  string // why we are offline

	log    *dash.Log
	alerts []events.Event // newest first
	filter dash.Filter
	paused bool

	mode   mode
	frozen []events.Event // the log as it was when selection started
	cursor int            // selected line in the visible log
	offset int            // first visible line, for scrolling

	search string // log filter text
	typing bool   // keystrokes go into search

	rules       []rules.Rule
	rulesCursor int

	reloading bool
	status    string
	statusBad bool
	statusID  int
}

func newModel(client *apiclient.Client, addr string) model {
	return model{
		client: client,
		addr:   addr,
		log:    dash.NewLog(1000),
	}
}

func (m model) Init() tea.Cmd {
	return fetchStats(m.client)
}

// Commands: each runs in the background and reports back with a message.

func fetchStats(c *apiclient.Client) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		snap, err := c.Stats(ctx, 20)
		return snapshotMsg{snap, err}
	}
}

func setRule(c *apiclient.Client, domain, action string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		r, err := c.SetRule(ctx, domain, action)
		return ruleSetMsg{r, err}
	}
}

func removeRule(c *apiclient.Client, domain string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return ruleRemovedMsg{domain, c.RemoveRule(ctx, domain)}
	}
}

func fetchRules(c *apiclient.Client) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		r, err := c.Rules(ctx)
		return rulesMsg{r, err}
	}
}

func reloadLists(c *apiclient.Client) tea.Cmd {
	return func() tea.Msg {
		// Downloading the lists can take a while.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		return reloadDoneMsg{c.Reload(ctx)}
	}
}

// say shows a status message in the footer for a few seconds.
func (m *model) say(text string, bad bool) tea.Cmd {
	m.statusID++
	m.status, m.statusBad = text, bad
	id := m.statusID
	return tea.Tick(4*time.Second, func(time.Time) tea.Msg { return clearStatusMsg{id} })
}

// shown is what the log displays right now: the live log, or the frozen
// copy while selecting, narrowed by the filter and the search text.
func (m model) shown() []events.Event {
	src := m.frozen
	if m.mode != modeSelect {
		src = m.log.Latest(m.log.Len(), dash.ShowAll)
	}
	needle := strings.ToLower(m.search)
	out := make([]events.Event, 0, len(src))
	for _, e := range src {
		if !m.filter.Match(e) {
			continue
		}
		if needle != "" && !strings.Contains(e.Name, needle) && !strings.Contains(e.Client, needle) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func (m model) selected() (events.Event, bool) {
	s := m.shown()
	if m.mode != modeSelect || m.cursor >= len(s) {
		return events.Event{}, false
	}
	return s[m.cursor], true
}

// logRows is how many log lines fit; view.go uses the same number.
func (m model) logRows() int {
	_, botH, _ := m.layout()
	rows := botH - 3 // border and title
	if m.mode == modeSelect {
		rows-- // detail line for the selected query
	}
	return max(rows, 1)
}

// move changes the selection and scrolls to keep it on screen.
func (m *model) move(delta int) {
	n := len(m.shown())
	if n == 0 {
		return
	}
	m.cursor = min(max(m.cursor+delta, 0), n-1)
	rows := m.logRows()
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+rows {
		m.offset = m.cursor - rows + 1
	}
}

func (m *model) startSelect() {
	m.frozen = m.log.Latest(m.log.Len(), dash.ShowAll)
	m.mode = modeSelect
	m.cursor, m.offset = 0, 0
}

func (m *model) stopSelect() {
	m.mode = modeLive
	m.frozen = nil
	m.cursor, m.offset = 0, 0
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.move(0) // keep the selection visible after a resize

	case tea.KeyPressMsg:
		return m.key(msg.String())

	case snapshotMsg:
		if msg.err != nil {
			m.live = false
			m.lastErr = msg.err.Error()
		} else {
			m.snap, m.haveSnap, m.live, m.lastErr = msg.snap, true, true, ""
		}
		// Poll again in a second, whether this one worked or not.
		return m, tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })

	case tickMsg:
		return m, fetchStats(m.client)

	case eventMsg:
		e := events.Event(msg)
		if e.Kind == "alert" {
			m.alerts = append([]events.Event{e}, m.alerts...)
			if len(m.alerts) > maxAlerts {
				m.alerts = m.alerts[:maxAlerts]
			}
		} else if !m.paused {
			m.log.Add(e) // while selecting, the frozen copy is shown instead
		}

	case streamRestartMsg:
		m.log.Clear()
		m.alerts = nil

	case ruleSetMsg:
		if msg.err != nil {
			return m, m.say("rule not saved: "+msg.err.Error(), true)
		}
		verb := "allowed"
		if msg.rule.Action == rules.Block {
			verb = "blocked"
		}
		return m, m.say(verb+" "+msg.rule.Domain+" and its subdomains", false)

	case ruleRemovedMsg:
		if msg.err != nil {
			return m, m.say("rule not removed: "+msg.err.Error(), true)
		}
		return m, tea.Batch(m.say("removed the rule for "+msg.domain, false), fetchRules(m.client))

	case rulesMsg:
		if msg.err != nil {
			return m, m.say("could not load rules: "+msg.err.Error(), true)
		}
		m.rules = msg.rules
		m.rulesCursor = min(m.rulesCursor, max(len(m.rules)-1, 0))

	case reloadDoneMsg:
		m.reloading = false
		if msg.err != nil {
			return m, m.say("reload failed, previous lists kept: "+msg.err.Error(), true)
		}
		return m, m.say("blocklists reloaded", false)

	case clearStatusMsg:
		if msg.id == m.statusID {
			m.status = ""
		}
	}
	return m, nil
}

func (m model) key(k string) (tea.Model, tea.Cmd) {
	if k == "ctrl+c" {
		return m, tea.Quit
	}

	if m.typing {
		switch k {
		case "enter":
			m.typing = false
		case "esc":
			m.typing, m.search = false, ""
		case "backspace":
			if r := []rune(m.search); len(r) > 0 {
				m.search = string(r[:len(r)-1])
			}
		default:
			if len([]rune(k)) == 1 { // a printable character
				m.search += strings.ToLower(k)
			}
		}
		m.cursor, m.offset = 0, 0
		return m, nil
	}

	switch m.mode {
	case modeHelp:
		m.mode = modeLive // any key closes the help
		return m, nil

	case modeRules:
		switch k {
		case "esc", "R", "q":
			m.mode = modeLive
		case "up", "k":
			m.rulesCursor = max(m.rulesCursor-1, 0)
		case "down", "j":
			m.rulesCursor = min(m.rulesCursor+1, max(len(m.rules)-1, 0))
		case "d", "delete", "backspace":
			if m.rulesCursor < len(m.rules) {
				return m, removeRule(m.client, m.rules[m.rulesCursor].Domain)
			}
		}
		return m, nil
	}

	switch k {
	case "q":
		return m, tea.Quit
	case "?":
		m.mode = modeHelp
	case "/":
		m.typing = true
	case "esc":
		if m.mode == modeSelect {
			m.stopSelect()
		} else {
			m.search = ""
		}
	case "up", "k":
		if m.mode != modeSelect {
			m.startSelect()
		} else {
			m.move(-1)
		}
	case "down", "j":
		if m.mode != modeSelect {
			m.startSelect()
		} else {
			m.move(1)
		}
	case "pgup":
		m.move(-m.logRows())
	case "pgdown":
		m.move(m.logRows())
	case "f":
		m.filter = m.filter.Next()
		m.cursor, m.offset = 0, 0
	case "p":
		m.paused = !m.paused
	case "c":
		m.log.Clear()
		m.alerts = nil
		m.stopSelect()
	case "r":
		if !m.reloading {
			m.reloading = true
			return m, tea.Batch(m.say("reloading blocklists…", false), reloadLists(m.client))
		}
	case "R":
		m.mode = modeRules
		return m, fetchRules(m.client)
	case "a", "A", "b", "B":
		e, ok := m.selected()
		if !ok {
			return m, m.say("select a query first (↑/↓)", true)
		}
		domain := e.Name
		if k == "A" || k == "B" {
			// The whole site: the registrable domain, e.g. "example.co.uk".
			if reg := psl.Default.Split(e.Name).Registrable; reg != "" {
				domain = reg
			}
		}
		action := rules.Allow
		if k == "b" || k == "B" {
			action = rules.Block
		}
		return m, setRule(m.client, domain, action)
	}
	return m, nil
}

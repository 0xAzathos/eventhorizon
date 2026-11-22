package main

import (
	"context"
	"time"

	tea "charm.land/bubbletea/v2"

	"eventhorizon/internal/apiclient"
	"eventhorizon/internal/dash"
	"eventhorizon/internal/events"
	"eventhorizon/internal/stats"
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
)

const maxAlerts = 50

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

// fetchStats asks for a snapshot in the background; the answer arrives
// as a snapshotMsg.
func fetchStats(c *apiclient.Client) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		snap, err := c.Stats(ctx, 20)
		return snapshotMsg{snap, err}
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height

	case tea.KeyPressMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "p":
			m.paused = !m.paused
		case "f":
			m.filter = m.filter.Next()
		case "c":
			m.log.Clear()
			m.alerts = nil
		}

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
			m.log.Add(e)
		}

	case streamRestartMsg:
		m.log.Clear()
		m.alerts = nil
	}
	return m, nil
}

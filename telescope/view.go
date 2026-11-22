package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"eventhorizon/internal/dash"
	"eventhorizon/internal/events"
)

const (
	minWidth  = 80
	minHeight = 24
)

func (m model) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	v.WindowTitle = "telescope · eventhorizon"
	return v
}

func (m model) render() string {
	W, H := m.width, m.height
	if W == 0 {
		return "" // no size yet; the first WindowSizeMsg follows right away
	}
	if W < minWidth || H < minHeight {
		msg := sDim.Render(fmt.Sprintf("telescope needs %d×%d, this terminal is %d×%d", minWidth, minHeight, W, H))
		return lipgloss.Place(W, H, lipgloss.Center, lipgloss.Center, msg)
	}

	// Rows: header 1, cards 5, middle, bottom, footer 1.
	avail := H - 7
	midH := max(9, avail*2/5)
	botH := avail - midH
	leftW := W * 3 / 5
	rightW := W - leftW
	// Below the alerts sits "Top clients", but only if both fit; on short
	// terminals the alerts get the whole column.
	alertsH, clientsH := botH, 0
	if botH >= 12 {
		alertsH = botH / 2
		clientsH = botH - alertsH
	}
	right := m.alertsPanel(rightW, alertsH)
	if clientsH > 0 {
		right = lipgloss.JoinVertical(lipgloss.Left, right, m.clientsPanel(rightW, clientsH))
	}

	return lipgloss.JoinVertical(lipgloss.Left,
		m.header(W),
		m.cards(W),
		lipgloss.JoinHorizontal(lipgloss.Top,
			m.chartPanel(leftW, midH),
			m.topBlockedPanel(rightW, midH),
		),
		lipgloss.JoinHorizontal(lipgloss.Top,
			m.logPanel(leftW, botH),
			right,
		),
		m.footer(W),
	)
}

func (m model) header(w int) string {
	left := sBrand.Render(" ◉ eventhorizon") + sDim.Render("  telescope")

	var right string
	switch {
	case m.live:
		up := dash.Uptime(time.Since(m.snap.Started))
		right = fg(cGreen).Render("● live") + sDim.Render("  up "+up+"  "+m.addr+" ")
	case !m.haveSnap && m.lastErr == "":
		right = fg(cAmber).Render("● connecting") + sDim.Render("  "+m.addr+" ")
	default:
		reason := dash.Truncate(m.lastErr, max(w/2, 10))
		right = fg(cRed).Render("● offline") + sDim.Render("  "+reason+" ")
	}
	return spread(w, left, right)
}

type card struct {
	label, value, sub string
	color             lipgloss.Style
}

func (m model) cards(w int) string {
	t := m.snap.Totals
	rate := dash.Rate(m.snap.PerSecond, 10)

	alerts := card{"THREAT ALERTS", dash.Count(t.Alerts), "all clear", fg(cGreen)}
	if t.Alerts > 0 {
		alerts.sub, alerts.color = "see alerts below", fg(cPink)
	}
	cards := []card{
		{"QUERIES", dash.Count(t.Queries), fmt.Sprintf("%.1f per second", rate), sText},
		{"BLOCKED", dash.Count(t.Blocked), dash.Percent(t.Blocked, t.Queries) + " of queries", fg(cRed)},
		{"FROM CACHE", dash.Count(t.Cached), dash.Percent(t.Cached, t.Cached+t.Allowed) + " hit rate", fg(cBlue)},
		{"SUSPICIOUS", dash.Count(t.Suspicious), "names flagged", fg(cAmber)},
		alerts,
	}

	cw := w / len(cards)
	boxes := make([]string, len(cards))
	for i, c := range cards {
		width := cw
		if i == len(cards)-1 {
			width = w - cw*(len(cards)-1) // last card takes the remainder
		}
		inner := width - 4
		boxes[i] = panel(width, 5, []string{
			sDim.Render(dash.Truncate(c.label, inner)),
			c.color.Bold(true).Render(dash.Truncate(c.value, inner)),
			sDim.Render(dash.Truncate(c.sub, inner)),
		})
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, boxes...)
}

func (m model) chartPanel(w, h int) string {
	inner := w - 4
	legend := fg(cGreen).Render("█") + sDim.Render(" allowed  ") + fg(cRed).Render("█") + sDim.Render(" blocked")
	lines := []string{spread(inner, sTitle.Render("Queries per second"), legend)}

	const axisW = 6        // "12.3k "
	chartRows := h - 2 - 2 // minus border, title and time axis
	chartW := inner - axisW
	rows, peak := dash.Bars(m.snap.PerSecond, chartW, chartRows)

	for r, row := range rows {
		label := ""
		switch r {
		case 0:
			if peak > 0 {
				label = dash.Count(uint64(peak))
			}
		case len(rows) - 1:
			label = "0"
		}
		lines = append(lines, sDim.Render(padLeft(label, axisW-1)+" ")+renderCells(row))
	}

	// Label the span the bars actually cover, using the same layout math
	// as dash.Bars.
	shown, colW := dash.Columns(len(m.snap.PerSecond), chartW)
	used := shown * colW
	axis := padLeft("now", chartW)
	if used > 8 {
		axis = spaces(chartW-used) + padRight(fmt.Sprintf("-%ds", shown), used-3) + "now"
	}
	lines = append(lines, sDim.Render(spaces(axisW)+axis))
	return panel(w, h, lines)
}

// renderCells styles one chart row, one Render call per run of same
// colored cells rather than per cell.
func renderCells(row []dash.Cell) string {
	var b strings.Builder
	for i := 0; i < len(row); {
		j := i
		var run strings.Builder
		for j < len(row) && row[j].Kind == row[i].Kind {
			run.WriteRune(row[j].Ch)
			j++
		}
		switch row[i].Kind {
		case dash.Allowed:
			b.WriteString(fg(cGreen).Render(run.String()))
		case dash.Blocked:
			b.WriteString(fg(cRed).Render(run.String()))
		default:
			b.WriteString(run.String())
		}
		i = j
	}
	return b.String()
}

func (m model) topBlockedPanel(w, h int) string {
	inner := w - 4
	lines := []string{sTitle.Render("Top blocked")}
	entries := m.snap.TopBlocked
	if len(entries) == 0 {
		return panel(w, h, append(lines, sDim.Render("nothing blocked yet")))
	}

	top := entries[0].Count
	const countW = 7
	for _, e := range entries[:min(len(entries), max(h-3, 0))] {
		name := dash.Truncate(e.Key, inner-countW-1)
		// A faint bar behind the count shows each entry's share of the top.
		barW := int(float64(countW) * float64(e.Count) / float64(top))
		count := padLeft(dash.Count(e.Count), countW)
		bar := lipgloss.NewStyle().Foreground(cRed).Background(lipgloss.Color("#3B1F24")).Render(count[:barW]) + fg(cRed).Render(count[barW:])
		lines = append(lines, bar+" "+sText.Render(name))
	}
	return panel(w, h, lines)
}

func (m model) logPanel(w, h int) string {
	inner := w - 4
	status := sDim.Render("filter: ") + sKey.Render(m.filter.String())
	if m.paused {
		status = fg(cAmber).Bold(true).Render("PAUSED  ") + status
	}
	lines := []string{spread(inner, sTitle.Render("Live queries"), status)}

	shown := m.log.Latest(h-3, m.filter)
	if len(shown) == 0 {
		return panel(w, h, append(lines, sDim.Render("waiting for queries…")))
	}

	// The type column is as wide as the longest type on screen, so a log
	// of plain "A" queries does not leave a gap.
	typeW := 1
	for _, e := range shown {
		typeW = max(typeW, len(e.Type))
	}
	// time(8) sym(1) action(8) type, single spaces between.
	fixed := 8 + 1 + 1 + 1 + 8 + 1 + typeW + 1
	clientW := 0
	if inner >= 90 {
		clientW = 16
	}
	for _, e := range shown {
		lines = append(lines, logLine(e, typeW, inner-fixed-clientW, clientW))
	}
	return panel(w, h, lines)
}

func logLine(e events.Event, typeW, nameW, clientW int) string {
	sym, s := actionStyle(e.Action)
	tag := ""
	if e.Via != "" {
		tag = " [cname]" // blocked because its alias points at a tracker
	}
	if e.Suspicious != "" {
		tag += " [" + e.Suspicious + "]"
	}
	name := dash.Truncate(e.Name, nameW-len(tag))

	line := sDim.Render(e.Time.Local().Format("15:04:05")) + " " +
		s.Render(sym) + " " +
		s.Render(padRight(e.Action, 8)) + " " +
		sDim.Render(padRight(e.Type, typeW)) + " " +
		sText.Render(name) + fg(cAmber).Bold(true).Render(tag)
	if clientW > 0 {
		// Measure in columns, not bytes: "…" is 3 bytes but 1 column.
		used := lipgloss.Width(name) + lipgloss.Width(tag)
		line += spaces(nameW-used) + sDim.Render(padLeft(dash.Truncate(e.Client, clientW), clientW))
	}
	return line
}

func (m model) alertsPanel(w, h int) string {
	inner := w - 4
	if len(m.alerts) == 0 {
		return panel(w, h, []string{
			sTitle.Render("Threat alerts"),
			fg(cGreen).Render("✓ no threats detected"),
			sDim.Render(dash.Truncate("watching for DGA malware and DNS tunneling", inner)),
		})
	}

	lines := []string{fg(cPink).Bold(true).Render(fmt.Sprintf("Threat alerts (%d)", len(m.alerts)))}
	for _, a := range m.alerts {
		if len(lines)+2 > h-2 {
			break
		}
		kind := strings.ToUpper(a.Alert)
		head := sDim.Render(a.Time.Local().Format("15:04:05")) + " " +
			fg(cPink).Bold(true).Render(kind) + " " +
			sText.Render(a.Client) + sDim.Render(fmt.Sprintf(" ×%d", a.Count))
		detail := strings.Join(a.Examples, ", ")
		if a.Domain != "" {
			detail = "→ " + a.Domain + "  " + detail
		}
		lines = append(lines, head, sDim.Render("  "+dash.Truncate(detail, inner-2)))
	}
	return panel(w, h, lines)
}

func (m model) clientsPanel(w, h int) string {
	inner := w - 4
	lines := []string{sTitle.Render("Top clients")}
	if len(m.snap.TopClients) == 0 {
		return panel(w, h, append(lines, sDim.Render("no clients yet")))
	}
	const countW = 7
	for _, e := range m.snap.TopClients[:min(len(m.snap.TopClients), max(h-3, 0))] {
		lines = append(lines, fg(cCyan).Render(padLeft(dash.Count(e.Count), countW))+" "+
			sText.Render(dash.Truncate(e.Key, inner-countW-1)))
	}
	return panel(w, h, lines)
}

func (m model) footer(w int) string {
	keys := []struct{ k, d string }{{"q", "quit"}, {"p", "pause"}, {"f", "filter"}, {"c", "clear"}}
	left := " "
	for _, k := range keys {
		left += sKey.Render(k.k) + sDim.Render(" "+k.d+"   ")
	}
	// Upstream health: a green or red dot per resolver, so a failover is
	// visible at a glance.
	right := ""
	for _, u := range m.snap.Upstreams {
		dot := fg(cGreen).Render("●")
		if !u.Up {
			dot = fg(cRed).Render("●")
		}
		host, _, err := net.SplitHostPort(u.Addr)
		if err != nil {
			host = u.Addr
		}
		label := " " + host
		if u.Encrypted {
			label += " tls"
		}
		right += dot + sDim.Render(label+"  ")
	}
	right += sDim.Render(fmt.Sprintf("blocklist %s · cache %s ",
		dash.Count(uint64(m.snap.Blocklist)), dash.Count(uint64(m.snap.CacheSize))))
	return spread(w, left, right)
}

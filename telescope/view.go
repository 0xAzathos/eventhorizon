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

// layout splits the screen: header 1, cards 5, middle, bottom, footer 1.
// model.go uses it too, to know how many log lines fit.
func (m model) layout() (midH, botH, leftW int) {
	avail := m.height - 7
	midH = max(9, avail*2/5)
	botH = avail - midH
	leftW = m.width * 3 / 5
	return midH, botH, leftW
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

	switch m.mode {
	case modeHelp:
		return lipgloss.JoinVertical(lipgloss.Left, m.header(W), m.helpScreen(W, H-2), m.footer(W))
	case modeRules:
		return lipgloss.JoinVertical(lipgloss.Left, m.header(W), m.rulesScreen(W, H-2), m.footer(W))
	}

	midH, botH, leftW := m.layout()
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

	// Title line: what the log is showing and how to steer it.
	var status string
	switch {
	case m.typing:
		status = sKey.Render("/") + sText.Render(m.search) + fg(cCyan).Render("▌") + sDim.Render("  enter done · esc clear")
	case m.mode == modeSelect:
		status = fg(cViolet).Bold(true).Render("SELECT") + sDim.Render("  a allow · b block · esc live")
	default:
		status = sDim.Render("filter: ") + sKey.Render(m.filter.String())
		if m.search != "" {
			status = sDim.Render("search: ") + sKey.Render(m.search) + sDim.Render("  ") + status
		}
		if m.paused {
			status = fg(cAmber).Bold(true).Render("PAUSED  ") + status
		}
	}
	lines := []string{spread(inner, sTitle.Render("Live queries"), status)}

	shown := m.shown()
	if m.mode == modeSelect {
		lines = append(lines, m.detailLine(inner))
	}
	if len(shown) == 0 {
		empty := "waiting for queries…"
		if m.search != "" || m.filter != dash.ShowAll {
			empty = "nothing matches"
		}
		return panel(w, h, append(lines, sDim.Render(empty)))
	}

	rows := m.logRows()
	end := min(m.offset+rows, len(shown))
	visible := shown[min(m.offset, end):end]

	// The type column is as wide as the longest type on screen, so a log
	// of plain "A" queries does not leave a gap.
	typeW := 1
	for _, e := range visible {
		typeW = max(typeW, len(e.Type))
	}
	// gutter(2) time(8) sym(1) action(8) type, single spaces between.
	fixed := 2 + 8 + 1 + 1 + 1 + 8 + 1 + typeW + 1
	clientW := 0
	if inner >= 90 {
		clientW = 16
	}
	for i, e := range visible {
		gutter := "  "
		if m.mode == modeSelect && m.offset+i == m.cursor {
			gutter = fg(cViolet).Bold(true).Render("▸ ")
		}
		lines = append(lines, gutter+logLine(e, typeW, inner-fixed-clientW, clientW))
	}
	return panel(w, h, lines)
}

// detailLine explains the selected query: why it was blocked, which
// rule matched, which client asked.
func (m model) detailLine(inner int) string {
	e, ok := m.selected()
	if !ok {
		return sDim.Render("nothing selected")
	}
	parts := []string{e.Name}
	if e.Rule != "" {
		why := "rule " + e.Rule
		if e.Via != "" {
			why += " via " + e.Via
		}
		parts = append(parts, why)
	}
	parts = append(parts, "from "+e.Client)
	return fg(cViolet).Render(dash.Truncate(strings.Join(parts, " · "), inner))
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

var helpKeys = []struct{ key, what string }{
	{"↑ ↓  k j", "select a query (freezes the log)"},
	{"pgup pgdn", "move a page"},
	{"a  /  A", "allow the selected name  /  its whole domain"},
	{"b  /  B", "block the selected name  /  its whole domain"},
	{"esc", "back to the live log, or clear the search"},
	{"/", "search the log by name or client"},
	{"f", "filter: all, blocked, suspicious"},
	{"p", "pause the live log"},
	{"c", "clear the log and alerts"},
	{"r", "reload the blocklists"},
	{"R", "your rules (d deletes one)"},
	{"?", "this help"},
	{"q", "quit"},
}

func (m model) helpScreen(w, h int) string {
	lines := []string{sTitle.Render("Keys"), ""}
	for _, k := range helpKeys {
		lines = append(lines, sKey.Render(padRight(k.key, 12))+sText.Render(k.what))
	}
	lines = append(lines, "", sDim.Render("Rules cover the domain and all of its subdomains, and beat the blocklists."),
		sDim.Render("Press any key to close."))
	return panel(w, h, lines)
}

func (m model) rulesScreen(w, h int) string {
	inner := w - 4
	lines := []string{spread(inner, sTitle.Render(fmt.Sprintf("Your rules (%d)", len(m.rules))),
		sDim.Render("↑↓ select · d delete · esc back"))}
	if len(m.rules) == 0 {
		lines = append(lines, "", sDim.Render("No rules yet. Select a query in the log and press a or b."))
		return panel(w, h, lines)
	}
	rows := h - 3
	start := max(0, m.rulesCursor-rows+1)
	for i := start; i < len(m.rules) && i < start+rows; i++ {
		r := m.rules[i]
		gutter := "  "
		if i == m.rulesCursor {
			gutter = fg(cViolet).Bold(true).Render("▸ ")
		}
		action := fg(cGreen).Render(padRight(r.Action, 6))
		if r.Action == "block" {
			action = fg(cRed).Render(padRight(r.Action, 6))
		}
		lines = append(lines, gutter+action+" "+sText.Render(dash.Truncate(r.Domain, inner-10)))
	}
	return panel(w, h, lines)
}

func (m model) footer(w int) string {
	left := " "
	switch {
	case m.status != "":
		s := fg(cGreen)
		if m.statusBad {
			s = fg(cRed)
		}
		left += s.Render(dash.Truncate(m.status, w/2))
	default:
		keys := []struct{ k, d string }{{"?", "help"}, {"/", "search"}, {"↑↓", "select"}, {"r", "reload"}, {"R", "rules"}, {"q", "quit"}}
		for _, k := range keys {
			left += sKey.Render(k.k) + sDim.Render(" "+k.d+"  ")
		}
	}

	// Refused queries: clients turned away by the allow list or rate
	// limit. Red when nonzero, so a device blocked by mistake shows up.
	right := sDim.Render("refused 0  ")
	if n := m.snap.Totals.Refused; n > 0 {
		right = fg(cRed).Render("refused "+dash.Count(n)) + "  "
	}
	// Upstream health: a green or red dot per resolver.
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

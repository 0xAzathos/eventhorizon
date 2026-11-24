package main

import (
	"image/color"

	"charm.land/lipgloss/v2"
)

// A dark "deep space" palette: violet for the brand, then one meaning per
// color everywhere: green allowed, red blocked, blue cached, amber
// suspicious, pink threats.
var (
	cViolet = lipgloss.Color("#A78BFA")
	cCyan   = lipgloss.Color("#22D3EE")
	cText   = lipgloss.Color("#E5E7EB")
	cDim    = lipgloss.Color("#6B7280")
	cFaint  = lipgloss.Color("#374151")
	cGreen  = lipgloss.Color("#34D399")
	cRed    = lipgloss.Color("#F87171")
	cBlue   = lipgloss.Color("#60A5FA")
	cAmber  = lipgloss.Color("#FBBF24")
	cPink   = lipgloss.Color("#F472B6")
)

func fg(c color.Color) lipgloss.Style {
	return lipgloss.NewStyle().Foreground(c)
}

var (
	sText  = fg(cText)
	sDim   = fg(cDim)
	sTitle = fg(cText).Bold(true)
	sBrand = fg(cViolet).Bold(true)
	sKey   = fg(cCyan).Bold(true)
)

// actionStyle maps a query outcome to its symbol and color.
func actionStyle(action string) (symbol string, s lipgloss.Style) {
	switch action {
	case "blocked":
		return "✕", fg(cRed)
	case "cached":
		return "◆", fg(cBlue)
	case "servfail":
		return "!", fg(cAmber)
	case "local":
		return "○", fg(cDim)
	default:
		return "●", fg(cGreen)
	}
}

// panel draws a rounded box exactly w by h cells. Lip Gloss v2 counts the
// border and padding inside Width and Height, so the inner area is
// (w-4) by (h-2). Lines must already fit; extra lines are dropped and
// missing ones are left blank.
func panel(w, h int, lines []string) string {
	inner := max(h-2, 0)
	if len(lines) > inner {
		lines = lines[:inner]
	}
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(cFaint).
		Padding(0, 1).
		Width(w).
		Height(h).
		Render(joinLines(lines))
}

func joinLines(lines []string) string {
	out := ""
	for i, l := range lines {
		if i > 0 {
			out += "\n"
		}
		out += l
	}
	return out
}

// spread puts left and right on one line of width w, filling the gap.
func spread(w int, left, right string) string {
	gap := w - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		return left
	}
	return left + spaces(gap) + right
}

func spaces(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = ' '
	}
	return string(b)
}

// padLeft right aligns plain text s in a field of n characters.
func padLeft(s string, n int) string {
	return spaces(n-lipgloss.Width(s)) + s
}

// padRight left aligns plain text s in a field of n characters.
func padRight(s string, n int) string {
	return s + spaces(n-lipgloss.Width(s))
}

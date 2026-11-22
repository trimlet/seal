package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/trimlet/gui"
)

type line = gui.Line

func (m *model) Render(cols, rows int) []line {
	m.cols, m.rows = cols, rows
	var lines []line
	switch m.screen {
	case screenList:
		lines = m.renderList()
	case screenForm:
		lines = m.form.render(cols)
	case screenCodes:
		lines = m.renderCodes()
	case screenBusy:
		lines = []line{{gui.Colored(m.busy, gui.Muted)}}
	case screenTime:
		lines = m.renderTime()
	case screenResult:
		lines = append(m.result, m.footer(m.resultHint())...)
	case screenSecret:
		lines = m.renderSecret()
	}
	if m.dialog != nil {
		return gui.WithDialog(lines, m.dialog, cols, rows)
	}
	return lines
}

// footer is the status, if any, and the hint.
func (m *model) footer(hint string) []line {
	lines := []line{nil}
	if m.status != nil {
		lines = append(lines, m.status, nil)
	}
	return append(lines, line{gui.Colored(hint, gui.Muted)})
}

// listRoom is how many rows of the list fit: the window less the top margin,
// the two menu entries, the status and the hint.
func (m *model) listRoom() int { return max(m.rows-9, 1) }

// renderList draws Gino's codes (the secret is never shown here), then the menu.
func (m *model) renderList() []line {
	reqs := m.store.Requests
	var lines []line
	if len(reqs) == 0 {
		lines = append(lines, line{gui.Colored("No codes yet: press 1 to ask for a secret.", gui.Muted)})
	}
	width := 0
	for _, r := range reqs {
		width = max(width, len([]rune(r.Name)))
	}
	width = min(width, max(m.cols/2, 10))
	room := m.listRoom()
	start := min(max(m.cursor-room/2, 0), max(len(reqs)-room, 0))
	end := min(start+room, len(reqs))
	if start > 0 {
		lines = append(lines, line{gui.Colored(fmt.Sprintf("  ↑ %d more", start), gui.Muted)})
	}
	for i := start; i < end; i++ {
		name := fmt.Sprintf("%-*s", width, gui.Truncate(reqs[i].Name, width))
		state, more := m.rowState(reqs[i])
		head := gui.Plain("  " + name)
		if i == m.cursor {
			head = gui.Strong("› "+name, gui.Accent)
		}
		lines = append(lines, append(line{head, gui.Plain("   ")}, state...))
		if more != "" {
			lines = append(lines, line{gui.Plain(strings.Repeat(" ", width+5)), gui.Colored(more, gui.Muted)})
		}
	}
	if end < len(reqs) {
		lines = append(lines, line{gui.Colored(fmt.Sprintf("  ↓ %d more", len(reqs)-end), gui.Muted)})
	}
	if len(reqs) > 0 {
		lines = append(lines, nil)
	}
	lines = append(lines,
		line{gui.Plain("  "), gui.Strong("1", gui.Accent), gui.Plain("  Ask for a secret")},
		line{gui.Plain("  "), gui.Strong("2", gui.Accent), gui.Plain("  Reply with a secret")})
	hint := "1 ask for a secret · 2 reply with a secret · " + gui.FullScreenKey + " full screen · esc quit"
	if m.cursor < len(reqs) && m.arrived(reqs[m.cursor]) {
		hint = "enter open · " + hint
	}
	if len(reqs) > 1 {
		hint = "↑/↓ move · " + hint
	}
	return append(lines, m.footer(hint)...)
}

// renderCodes shows the two codes of the new request, to send on two different channels.
func (m *model) renderCodes() []line {
	r := m.made
	width := max(len(r.Code), len(r.Unlock))
	entry := func(num, label, value string, key rune) []line {
		return []line{
			{gui.Strong(num, gui.Accent), gui.Plain("  " + label)},
			{gui.Plain("   "), gui.Colored(value+strings.Repeat(" ", width-len(value)), gui.ValueFg),
				gui.Plain("   "), gui.Strong(string(key), gui.Accent), gui.Colored(" copy", gui.Muted)},
		}
	}
	lines := []line{{gui.Strong("Send these two to the sender on two different channels.", nil)}, nil}
	lines = append(lines, entry("1", "Code", r.Code, 'c')...)
	lines = append(lines, nil)
	lines = append(lines, entry("2", "Unlock code", r.Unlock, 'u')...)
	if !m.codesReady() { // the access key or a further place: Enter only after (decided)
		lines = append(lines, nil, line{gui.Colored(m.waitText(), gui.Muted)})
		return append(lines, m.footer("c copy the code · u copy the unlock code · esc cancel")...)
	}
	return append(lines, m.footer("c copy the code · u copy the unlock code · enter done · esc cancel")...)
}

// renderTime shows what Mario typed and the time the receiver has to read it.
func (m *model) renderTime() []line {
	muted := func(label, value string) line {
		return line{gui.Colored(gui.Truncate(label+": "+gui.DisplayText(value), m.cols-2), gui.Muted)}
	}
	lines := []line{
		{gui.Strong("Reply with a secret", nil)}, nil,
		muted("Code", group(m.sendCode)),
		muted("Unlock code", group(m.sendUnlock)),
		muted("Secret", m.sendSecret),
		nil,
	}
	choice := line{gui.Plain("Must be read within: ")}
	for i, h := range hourChoices {
		label := fmt.Sprintf("%d hours", h)
		if h == 1 {
			label = "1 hour"
		}
		s := gui.Plain("  " + label + "  ")
		if i == m.hours {
			s = gui.Strong("["+label+"]", gui.Accent)
			s.Text = " " + s.Text + " "
			s.Bg = gui.SelectedBg
		}
		choice = append(choice, gui.Plain(" "), s)
	}
	lines = append(lines, choice)
	if m.access.Key == "" { // the access key: Enter only after (decided)
		lines = append(lines, nil, line{gui.Colored(m.waitText(), gui.Muted)})
		return append(lines, m.footer("←/→ choose · esc cancel")...)
	}
	return append(lines, m.footer("←/→ choose · enter send · esc cancel")...)
}

func (m *model) resultHint() string {
	if m.retry {
		return "enter try again · esc back"
	}
	return "esc back"
}

// arrived says whether r's secret is on the server, ready to open.
func (m *model) arrived(r *Request) bool {
	rm := m.remote[r]
	return r.Outcome == "" && rm != nil && rm.state == "arrived"
}

// when writes a date and time as in the receipt row: Tue 24 Nov 11:04.
func when(t time.Time) string { return t.Local().Format("Mon 2 Jan 15:04") }

// rowState is what the list says of a request (never the secret), and an optional second line.
func (m *model) rowState(r *Request) (line, string) {
	red := func(s string) line { return line{gui.Colored(s, gui.Red)} }
	switch r.Outcome {
	case outcomeRead:
		return line{gui.Colored("read on this device · "+when(r.Ended), gui.Muted)}, ""
	case outcomeExpired:
		return red("✖ expired — nothing was sent."), ""
	case outcomeNotRead:
		return red("✖ expired — it arrived but was not read in time."), ""
	case outcomeElsewhere:
		return red("✖ delivered elsewhere · " + when(r.Ended) + " — not to this device."), "If it was not you, warn the sender."
	case outcomeNotRecv:
		return red("✖ not received — the connection failed while it was arriving."), "Ask the sender to send it again."
	case outcomeBroken:
		return red("✖ could not be opened."), ""
	case outcomeLapsed:
		return red("✖ expired."), ""
	case outcomeFull:
		return red("✖ the server is full — this code will not work. Make a new one later."), ""
	}
	rm := m.remote[r]
	if r.Unregistered {
		switch {
		case rm != nil && rm.state == "unregistered":
			return line{gui.Colored("? "+rm.err, gui.Muted)}, ""
		case rm != nil && rm.state == "registering":
			return line{gui.Colored("registering…", gui.Muted)}, ""
		}
		w := m.waitText()
		return line{gui.Colored(strings.ToLower(w[:1])+w[1:len(w)-1], gui.Muted)}, ""
	}
	switch {
	case rm == nil || rm.state == "checking":
		return line{gui.Colored("checking…", gui.Muted)}, ""
	case rm.state == "arrived":
		return line{gui.Strong("✔ arrived · "+timeLeft(rm.readBy.Sub(m.now())), gui.Accent)}, ""
	case rm.state == "error":
		return line{gui.Colored("? "+rm.err, gui.Muted)}, ""
	}
	return line{gui.Colored("waiting…", gui.Muted)}, ""
}

// timeLeft says how long is left to read: "23 h left", "40 min left".
func timeLeft(d time.Duration) string {
	if d >= time.Hour {
		return fmt.Sprintf("%d h left", int(d.Hours()))
	}
	return fmt.Sprintf("%d min left", max(int(d.Minutes()), 1))
}

// renderSecret shows the secret, once (or why it cannot be opened).
func (m *model) renderSecret() []line {
	lines := []line{{gui.Strong(m.opened.Name, nil)}, nil}
	if m.notice != nil {
		lines = append(lines, m.notice...)
		return append(lines, m.footer("esc close")...)
	}
	for _, l := range strings.Split(m.secret, "\n") {
		lines = append(lines, line{gui.Plain("  "), gui.Strong(l, gui.ValueFg)})
	}
	lines = append(lines, nil, line{gui.Colored("It will be deleted when you close this screen.", gui.Muted)})
	return append(lines, m.footer("c copy · esc close")...)
}

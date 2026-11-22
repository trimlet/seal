package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/trimlet/gui"
)

type screen int

const (
	screenList   screen = iota // the start: Gino's codes
	screenForm                 // questions, one after the other
	screenBusy                 // waiting for the server (and for Argon2id)
	screenCodes                // the code and the unlock code of a new request, to copy
	screenTime                 // Mario: how long the receiver has to read it, then send
	screenResult               // Mario: sent, or why not
	screenSecret               // Gino: the secret, once
)

// The times Mario can choose (decided: 1 hour, 2 hours, 24 hours, 24 preselected).
var hourChoices = []int{1, 2, 24}

const defaultHours = 2 // index of 24 hours

// model holds the state of Trimlet Seal and reacts to keys.
// It knows nothing about the window: copying, quitting and running in the user
// interface are done through callbacks.
type model struct {
	store  *Store
	srv    server
	screen screen
	cursor int // selected row of the list

	form *form
	busy string   // what screenBusy says
	made *Request // the request whose codes are on screenCodes: only in memory until Gino's Yes

	// The access key (block 5b, access.go).
	access      *Access
	work        *work  // the long work running, if any
	workErr     string // why the last work failed, until it is tried again
	registering bool   // a confirmed request is going to the server

	// Gino's reading.
	remote     map[*Request]*remote // what the server last said, per active request
	refreshing bool
	opened     *Request   // the request whose secret is on screenSecret
	secret     string     // the secret on screenSecret
	notice     []gui.Line // instead of the secret: why it is not there

	// Mario's send, between the questions and the answer of the server.
	sendCode   string // the code, 52 characters without dashes
	sendUnlock string
	sendSecret string
	hours      int // index in hourChoices
	result     []gui.Line
	retry      bool // the server could not be reached: enter tries again

	status gui.Line // message shown at the bottom (e.g. "✔ Code copied"), cleared by the next key
	cols   int
	rows   int

	copy   func(text string)
	quit   func()
	dialog *gui.Dialog // the window in the middle (quit, confirm the send), when open
	now    func() time.Time
	// async runs slow work (Argon2id, the network) away from the user interface;
	// ui runs f in the user interface and redraws, from any goroutine;
	// later runs f in the user interface after d (to try again).
	async func(f func())
	ui    func(f func())
	later func(d time.Duration, f func())
}

func newModel(s *Store, srv server) *model {
	return &model{
		store:  s,
		srv:    srv,
		access: &Access{},
		remote: map[*Request]*remote{},
		cols:   gui.DefaultCols,
		copy:   func(string) {},
		quit:   func() {},
		now:    time.Now,
		async:  func(f func()) { go f() },
		ui:     func(f func()) { f() },
		later:  func(time.Duration, func()) {},
	}
}

// start is the opening: ask the server about the codes, and, the first time, start the work for
// the access key at once, in the background.
func (m *model) start() {
	m.refresh()
	m.prepare()
}

// ---- Keys ----

func (m *model) Key(k string) {
	if m.dialog != nil {
		d := m.dialog
		m.dialog = nil
		if !d.Key(k) {
			m.dialog = d
		}
		return
	}
	if m.screen != screenForm {
		m.status = nil
	}
	switch m.screen {
	case screenList:
		switch k {
		case gui.KeyUp, gui.KeyDown:
			m.cursor = move(m.cursor, k, len(m.store.Requests))
		case gui.KeyEnter:
			if m.cursor < len(m.store.Requests) {
				m.openRequest(m.store.Requests[m.cursor])
			}
		case gui.KeyEsc:
			m.askQuit()
		}
	case screenForm:
		m.form.key(k)
	case screenCodes:
		switch {
		case k == gui.KeyEnter && m.codesReady():
			m.dialog = &gui.Dialog{
				Question: "Did you copy both codes?",
				Body:     []gui.Line{{gui.Plain("You will not see them again.")}},
				Answers:  []gui.Answer{{Key: 'y', Label: "Yes", Do: m.confirmMade}, {Key: 'n', Label: "No"}},
				Esc:      1,
			}
		case k == gui.KeyEsc:
			m.dialog = &gui.Dialog{
				Question: "Cancel this code?",
				Answers:  []gui.Answer{{Key: 'y', Label: "Yes", Do: m.cancelMade}, {Key: 'n', Label: "No"}},
				Esc:      1,
			}
		}
	case screenSecret:
		if k == gui.KeyEsc || k == gui.KeyEnter {
			m.closeSecret()
		}
	case screenTime:
		switch k {
		case gui.KeyLeft:
			m.hours = max(m.hours-1, 0)
		case gui.KeyRight:
			m.hours = min(m.hours+1, len(hourChoices)-1)
		case gui.KeyEnter:
			if m.access.Key != "" { // until the key is ready, Enter does nothing (decided)
				m.confirmSend()
			}
		case gui.KeyEsc:
			m.endSend()
		}
	case screenResult:
		switch {
		case k == gui.KeyEnter && m.retry:
			m.doSend()
		case k == gui.KeyEsc || k == gui.KeyEnter:
			m.endSend()
		}
	}
}

func (m *model) Rune(r rune) {
	if m.dialog != nil {
		d := m.dialog
		m.dialog = nil
		if !d.Rune(r) {
			m.dialog = d
		}
		return
	}
	if m.screen != screenForm {
		m.status = nil
	}
	switch m.screen {
	case screenList:
		switch r {
		case '1':
			m.ask()
		case '2':
			m.startSend()
		case 'q':
			m.askQuit()
		}
	case screenForm:
		m.form.rune(r)
	case screenCodes:
		switch r {
		case 'c':
			m.copy(m.made.Code)
			m.status = gui.Line{gui.Strong("✔ Code copied", gui.Amber)}
		case 'u':
			m.copy(m.made.Unlock)
			m.status = gui.Line{gui.Strong("✔ Unlock code copied", gui.Amber)}
		}
	case screenSecret:
		if r == 'c' && m.secret != "" {
			m.copy(m.secret)
			m.status = gui.Line{gui.Strong("✔ Copied", gui.Amber)}
		}
	}
}

func (m *model) Paste(text string) {
	if m.screen == screenForm {
		m.form.paste(text)
	}
}

func (m *model) CanPaste() bool { return m.screen == screenForm }

func (m *model) askQuit() { m.dialog = gui.QuitDialog("Trimlet Seal", m.quit) }

// move takes the cursor one step up or down in a list of n entries, going round.
func move(cursor int, k string, n int) int {
	if n == 0 {
		return 0
	}
	if k == gui.KeyUp {
		return (cursor - 1 + n) % n
	}
	return (cursor + 1) % n
}

// ---- Ask for a secret (Gino) ----

const nameQuestion = "Name this code (only you will see it)"

// ask asks the name of a new code, then makes it (docs/design.md section 3d, flow step 1).
func (m *model) ask() {
	if m.activeCount() >= maxActive {
		m.status = gui.Line{gui.Strong("✘ You already have 5 codes waiting. Wait for one of them to be used or to expire.", gui.Red)}
		return
	}
	m.checkKey()
	m.askName("", "")
}

func (m *model) askName(name, errMsg string) {
	m.form = newForm("Ask for a secret", []question{{label: nameQuestion, value: name}},
		func(answers []string) string {
			m.makeRequest(answers[0])
			return ""
		},
		func() { m.toList() })
	m.form.err = errMsg
	m.screen = screenForm
}

// makeRequest makes the key pair, the unlock code and its ticket (Argon2id), and shows the codes at
// once. Nothing is written or sent yet: the request goes to pending.json and to the server only after
// Gino's Yes (block 5b: closing before loses everything, decided).
func (m *model) makeRequest(name string) {
	m.screen, m.busy = screenBusy, "Making the code…"
	m.async(func() {
		req, err := m.newRequest(name)
		if err == nil {
			pub, _ := decode32(req.Code, keyLen)
			var ticket []byte
			ticket, _, err = unlockKeys(req.Unlock, pub)
			req.Ticket = b64(ticket)
		}
		m.ui(func() {
			if err != nil {
				m.askName(name, "Could not make the code: "+err.Error())
				return
			}
			m.made = req
			m.screen = screenCodes
			m.prepare() // a further place, if all are taken
		})
	})
}

// confirmMade is Yes to "Did you copy both codes?": the request is saved, and goes to the server.
func (m *model) confirmMade() {
	r := m.made
	r.Unregistered = true
	m.store.Requests = append(m.store.Requests, r)
	if err := m.store.save(); err != nil {
		m.store.Requests = m.store.Requests[:len(m.store.Requests)-1]
		m.status = gui.Line{gui.Strong("✘ Could not save: "+err.Error(), gui.Red)}
		return
	}
	m.made = nil
	m.cursor = len(m.store.Requests) - 1
	m.toList()
}

// cancelMade is Yes to "Cancel this code?": nothing was written or sent, so nothing is left.
func (m *model) cancelMade() {
	m.made = nil
	m.stopPlaceWork()
	m.toList()
}

// registerPending sends to the server, one at a time, the requests Gino confirmed, as soon as the key
// and a free place are there (docs/apps/seal.md section 5: the registration failures).
func (m *model) registerPending() {
	if m.registering {
		return
	}
	var r *Request
	for _, x := range m.store.Requests {
		if x.Outcome == "" && x.Unregistered {
			r = x
			break
		}
	}
	if r == nil {
		return
	}
	if m.access.Key == "" || m.access.Places <= m.taken() {
		m.prepare()
		return
	}
	m.registering = true
	m.remote[r] = &remote{state: "registering"}
	key := m.access.key()
	m.async(func() {
		ticket, err := base64.StdEncoding.DecodeString(r.Ticket)
		var ch challenge
		if err == nil {
			ch, err = m.srv.challenge(workCode)
		}
		if err == nil {
			code := plain(r.Code)
			err = m.srv.register(key, code, ticketHash(ticket), ch.Challenge, powSolve(ch.Challenge, code, ch.Difficulty))
		}
		m.ui(func() { m.registered(r, key, err) })
	})
}

// registered records the server's answer to a registration.
func (m *model) registered(r *Request, key []byte, err error) {
	m.registering = false
	switch {
	case err == nil:
		r.Unregistered, r.Keyed = false, true
		m.remote[r] = &remote{state: "waiting"}
		m.save()
		m.registerPending()
	case errors.Is(err, errUnknownKey):
		// Purged, or a year unused: a new key (2 minutes), then the registration goes on by itself.
		delete(m.remote, r)
		if b64(key) == m.access.Key {
			m.access.forget()
			m.saveAccess()
		}
		m.prepare()
	case errors.Is(err, errNoPlace):
		// The server counts more codes than this app: one more place, then again.
		delete(m.remote, r)
		if m.access.Places >= maxActive {
			m.remote[r] = &remote{state: "unregistered", err: "all 5 places hold a code — will try again when one ends"}
			m.later(time.Minute, m.registerPending)
			return
		}
		m.access.Places = m.taken()
		m.prepare()
	case errors.Is(err, errServerFull):
		r.end(outcomeFull, m.now())
		m.save()
		m.registerPending()
	default:
		msg := "could not reach the server — will try again"
		if !isNetwork(err) {
			msg = "the server answered " + err.Error() + " — will try again"
		}
		m.remote[r] = &remote{state: "unregistered", err: msg}
		m.later(30*time.Second, m.registerPending)
	}
}

func (m *model) newRequest(name string) (*Request, error) {
	code, key, err := newKeys()
	if err != nil {
		return nil, err
	}
	unlock, err := newUnlockCode()
	if err != nil {
		return nil, err
	}
	return &Request{Name: name, Code: code, Key: key, Unlock: unlock, Created: m.now()}, nil
}

// plain is a code as the server knows it: without dashes.
func plain(code string) string {
	s, _ := normalize(code)
	return s
}

// ---- Reply with a secret (Mario) ----

func (m *model) startSend() {
	m.hours = defaultHours
	m.checkKey() // the key's work, if missing, runs while Mario pastes and types
	m.askSend()
}

func (m *model) askSend() {
	qs := []question{
		{label: "Paste the code you received", check: checkCode},
		{label: "Unlock code", check: checkUnlock},
		{label: "Secret", check: checkSecret},
	}
	m.form = newForm("Reply with a secret", qs,
		func(a []string) string {
			m.sendCode, m.sendUnlock, m.sendSecret = plain(a[0]), plain(a[1]), a[2]
			m.screen = screenTime
			return ""
		},
		m.endSend)
	m.screen = screenForm
}

// askSecretAgain is "No" in the confirmation: the secret again, to fix it.
func (m *model) askSecretAgain() {
	m.form = newForm("Reply with a secret", []question{{label: "Secret", value: m.sendSecret, check: checkSecret}},
		func(a []string) string {
			m.sendSecret = a[0]
			m.screen = screenTime
			return ""
		},
		m.endSend)
	m.screen = screenForm
}

func checkCode(v string, _ []string) string {
	s, err := normalize(v)
	switch {
	case err == nil && len(s) == unlockLen:
		return "This is the unlock code: paste here the code, the long one"
	case err != nil || len(s) != codeLen:
		return "This is not a code: paste the whole code you received (52 characters, like QXJM-8VR2-…)"
	}
	if _, err := decode32(s, keyLen); err != nil {
		return "This is not a code: paste the whole code you received (52 characters, like QXJM-8VR2-…)"
	}
	return ""
}

func checkUnlock(v string, _ []string) string {
	s, err := normalize(v)
	switch {
	case err == nil && len(s) == codeLen:
		return "This is the code: paste here the unlock code, the short one"
	case err != nil || len(s) != unlockLen:
		return "This is not an unlock code: 12 characters, like K7QM-4XRT-9BZ2"
	}
	return ""
}

func checkSecret(v string, _ []string) string {
	if n := len(v); n > maxSecret {
		return fmt.Sprintf("Too long: at most 4 KB (this is %.1f KB)", float64(n)/1024)
	}
	return ""
}

// confirmSend opens the window in the middle: one code takes only one secret.
func (m *model) confirmSend() {
	m.dialog = &gui.Dialog{
		Question: "Send it? This code takes only one secret.",
		Answers:  []gui.Answer{{Key: 'y', Label: "Yes", Do: m.doSend}, {Key: 'n', Label: "No", Do: m.askSecretAgain}},
		Esc:      1,
	}
}

// doSend encrypts the secret for the code and gives it to the server with the ticket and Mario's
// access key.
func (m *model) doSend() {
	if m.access.Key == "" {
		m.screen = screenTime
		return
	}
	m.screen, m.busy = screenBusy, "Sending…"
	code, unlock, secret, hours := m.sendCode, m.sendUnlock, m.sendSecret, hourChoices[m.hours]
	key := m.access.key()
	m.async(func() {
		pub, err := decode32(code, keyLen)
		var ticket, k, sealed []byte
		if err == nil {
			ticket, k, err = unlockKeys(unlock, pub)
		}
		if err == nil {
			sealed, err = seal([]byte(secret), pub, k)
		}
		if err == nil {
			_, err = m.srv.send(key, code, ticket, sealed, hours)
		}
		m.ui(func() {
			if errors.Is(err, errUnknownKey) {
				// Purged since the check: a new key; Mario presses Enter and Yes again when it is
				// ready, the secret is still in memory.
				if b64(key) == m.access.Key {
					m.access.forget()
					m.saveAccess()
				}
				m.prepare()
				m.screen = screenTime
				return
			}
			m.showResult(err)
		})
	})
}

func (m *model) showResult(err error) {
	m.screen, m.retry = screenResult, false
	red := func(s string) gui.Line { return gui.Line{gui.Strong(s, gui.Red)} }
	more := func(s string) gui.Line { return gui.Line{gui.Plain("  " + s)} }
	switch {
	case err == nil:
		m.result = []gui.Line{{gui.Strong("✔ Sent.", gui.Accent)}, more("Only the receiver's app can open it, once.")}
	case errors.Is(err, errWrongTicket):
		m.result = []gui.Line{red("✖ The unlock code does not match this code."),
			more("Check that you pasted both correctly. If they are right, the code may have"),
			more("been changed on its way: tell the receiver, and do not send.")}
	case errors.Is(err, errNotFound):
		// Not there yet (Gino's work is not over) or expired: the server cannot tell (section 4).
		m.result = []gui.Line{red("✖ This code is not on the server yet, or it has expired."),
			more("Try again in a few minutes. If it still fails, ask the receiver for a new code.")}
	case errors.Is(err, errAlreadySent):
		m.result = []gui.Line{red("✖ A secret was already sent to this code. Ask the receiver for a new one.")}
	default:
		m.retry = true
		m.result = []gui.Line{red("✖ Not sent: " + err.Error() + ".")}
	}
	if !m.retry {
		m.sendSecret, m.sendUnlock = "", ""
	}
}

// endSend leaves Mario's screens, forgetting what was typed.
func (m *model) endSend() {
	m.sendCode, m.sendUnlock, m.sendSecret, m.result, m.retry = "", "", "", nil, false
	m.toList()
}

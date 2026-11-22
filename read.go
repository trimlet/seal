package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"time"

	"github.com/trimlet/gui"
)

// Gino reads (block 3, docs/design.md section 3d, flow step 4): on opening the app only asks the
// server whether something is there; the secret is fetched only on Enter on its row, shown once,
// and never written to disk.

// remote is what the server last said about an active request (not saved).
type remote struct {
	state  string // "checking", "waiting", "arrived", "error"; not on the server yet: "registering", "unregistered" (failed, err says why)
	readBy time.Time
	err    string
}

// toList goes back to the list and asks the server again about the active requests.
func (m *model) toList() {
	m.screen = screenList
	m.refresh()
}

// refresh deletes old keys and rows, sends to the server the confirmed requests not there yet,
// then asks the server about every other active request, one after the other, away from the user
// interface.
func (m *model) refresh() {
	if m.store.tidy(m.now()) {
		m.save()
	}
	m.registerPending()
	if m.refreshing {
		return
	}
	var reqs []*Request
	for _, r := range m.store.Requests {
		if r.Outcome == "" && !r.Unregistered {
			reqs = append(reqs, r)
			if m.remote[r] == nil {
				m.remote[r] = &remote{state: "checking"}
			}
		}
	}
	if len(reqs) == 0 {
		return
	}
	m.refreshing = true
	type answer struct {
		r   *Request
		st  remoteState
		err error
	}
	m.async(func() {
		var answers []answer
		for _, r := range reqs {
			ticket, err := m.ticketOf(r)
			var st remoteState
			if err == nil {
				st, err = m.srv.state(plain(r.Code), ticket)
			}
			answers = append(answers, answer{r, st, err})
		}
		m.ui(func() {
			m.refreshing = false
			for _, a := range answers {
				m.apply(a.r, a.st, a.err)
			}
			m.save()
		})
	})
}

// ticketOf is the ticket kept in pending.json, or computed from the unlock code (Argon2id).
func (m *model) ticketOf(r *Request) ([]byte, error) {
	if r.Ticket != "" {
		return base64.StdEncoding.DecodeString(r.Ticket)
	}
	pub, err := decode32(r.Code, keyLen)
	if err != nil {
		return nil, err
	}
	ticket, _, err := unlockKeys(r.Unlock, pub)
	return ticket, err
}

// apply records what the server said about r; a request that ended loses its keys.
func (m *model) apply(r *Request, st remoteState, err error) {
	if r.Outcome != "" {
		return
	}
	switch {
	case errors.Is(err, errNotFound):
		// Unknown to the server: nothing was sent within the 7 days.
		r.end(outcomeExpired, r.Created.Add(phase1))
	case err != nil:
		m.remote[r] = &remote{state: "error", err: err.Error()}
	case st.State == "waiting" || st.State == "arrived":
		m.remote[r] = &remote{state: st.State, readBy: st.ReadBy}
	case st.State == "expired":
		r.end(outcomeNotRead, m.now())
	case st.State == "delivered":
		r.end(r.deliveredOutcome(st.DeliveredAt), st.DeliveredAt)
	}
}

func (m *model) save() {
	if err := m.store.save(); err != nil {
		m.status = gui.Line{gui.Strong("✘ Could not save: "+err.Error(), gui.Red)}
	}
}

// openRequest fetches the secret of r from the server (once), opens it and shows it.
// The keys are deleted at once: the server has deleted the secret, nothing else can come.
func (m *model) openRequest(r *Request) {
	if rm := m.remote[r]; r.Outcome != "" || rm == nil || rm.state != "arrived" {
		return
	}
	// The time of this try is saved first, so that a delivery whose answer is lost is told from a theft
	// even if the app is closed before it knows.
	r.Tries = append(r.Tries, m.now())
	m.save()
	m.screen, m.busy = screenBusy, "Opening…"
	m.async(func() {
		secret, err := m.fetchAndOpen(r)
		var after *remoteState
		if failedOnTheWay(err) {
			// Did the server deliver it? Only the server knows.
			if ticket, terr := m.ticketOf(r); terr == nil {
				if st, serr := m.srv.state(plain(r.Code), ticket); serr == nil {
					after = &st
				}
			}
		}
		m.ui(func() { m.showSecret(r, secret, err, after) })
	})
}

// failedOnTheWay says whether err is the connection, not an answer of the server or the crypto.
func failedOnTheWay(err error) bool {
	var na *notArrived
	return err != nil && !errors.As(err, &na) && !errors.Is(err, errCannotOpen) &&
		!errors.Is(err, errNotFound) && !errors.Is(err, errWrongTicket)
}

func (m *model) fetchAndOpen(r *Request) ([]byte, error) {
	pub, err := decode32(r.Code, keyLen)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(r.Key)
	if err != nil {
		return nil, err
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, err
	}
	ticket, k, err := unlockKeys(r.Unlock, pub)
	if err != nil {
		return nil, err
	}
	sealed, err := m.srv.fetch(plain(r.Code), ticket)
	if err != nil {
		return nil, err
	}
	return open(sealed, priv, k)
}

// showSecret shows what Enter on a row gave: the secret, or why not. after is what the server said
// when the fetch failed on the way (nil if it could not be asked either).
func (m *model) showSecret(r *Request, secret []byte, err error, after *remoteState) {
	var na *notArrived
	if errors.As(err, &na) {
		after = &na.st
	}
	switch {
	case err == nil:
		r.end(outcomeRead, m.now())
		m.save()
		m.show(r, string(secret), nil)
	case errors.Is(err, errCannotOpen):
		r.end(outcomeBroken, m.now())
		m.save()
		m.show(r, "", []gui.Line{{gui.Strong("✖ Cannot be opened. Make a new code and ask the sender to send again.", gui.Red)}})
	case after != nil && after.State != "arrived":
		m.apply(r, *after, nil)
		m.save()
		if r.Outcome == outcomeNotRecv {
			m.show(r, "", []gui.Line{
				{gui.Strong("✖ Not received — the connection failed while it was arriving.", gui.Red)},
				{gui.Plain("  Ask the sender to send it again.")},
			})
			return
		}
		m.toList()
	default:
		// The server still holds it (or cannot be asked): Enter can try again.
		m.toList()
		m.status = gui.Line{gui.Strong("✘ "+r.Name+": "+err.Error()+". Try again.", gui.Red)}
	}
}

// show puts the secret (or a notice instead) on screenSecret.
func (m *model) show(r *Request, secret string, notice []gui.Line) {
	m.opened, m.secret, m.notice = r, secret, notice
	m.screen = screenSecret
}

// closeSecret forgets the secret shown.
func (m *model) closeSecret() {
	m.opened, m.secret, m.notice = nil, "", nil
	m.toList()
}

package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// Access keys for everyone (block 5b, docs/apps/seal.md sections 4 and 5). Every installed Seal,
// Gino's and Mario's, gets an anonymous access key from the server by itself, with ≈2 minutes of proof
// of work in the background the first time. A key holds 1 to 5 places, one code waiting in each; each
// further place costs the same work once, only when it is needed. The key is kept in access.json, next
// to pending.json (so deleting pending.json does not lose it).

// Access is the file access.json.
type Access struct {
	Key    string `json:"key,omitempty"`    // base64, given by the server: like a password for it
	Places int    `json:"places,omitempty"` // codes the key may have waiting at once

	path string
}

func accessPath(pending string) string { return filepath.Join(filepath.Dir(pending), "access.json") }

func loadAccess(path string) (*Access, error) {
	a := &Access{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, a); err != nil {
		return nil, err
	}
	return a, nil
}

// save writes the file, readable only by the user, replacing it in one step.
func (a *Access) save() error {
	if a.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(a.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.path)
}

func (a *Access) key() []byte {
	k, _ := base64.StdEncoding.DecodeString(a.Key)
	return k
}

// forget drops a key the server no longer knows (purged in an attack, or a year unused).
func (a *Access) forget() { a.Key, a.Places = "", 0 }

// work is the long proof of work (a key or a further place) running in the background.
type work struct {
	kind       string
	started    time.Time // the real clock: the time left is measured on this computer
	difficulty atomic.Uint64
	tries      atomic.Uint64
	stop       atomic.Bool
}

// The time of one try before Seal has measured this computer (the author's Mac), and the work of a
// key before the server has said it (≈2 minutes there).
const (
	tryTime     = 1600 * time.Microsecond
	keyWorkHint = 75_000
)

// left is the time the work should still take, from the speed of this computer.
func (w *work) left(now time.Time) time.Duration {
	d := w.difficulty.Load()
	if d == 0 {
		d = keyWorkHint
	}
	elapsed := now.Sub(w.started)
	per := tryTime
	if n := w.tries.Load(); n >= 50 {
		per = elapsed / time.Duration(n)
	}
	return time.Duration(d)*per - elapsed
}

// waitText is the line shown while one must wait for the work.
func (m *model) waitText() string {
	if m.workErr != "" {
		return "Setting up your secure access… " + m.workErr + ", trying again."
	}
	left := 2 * time.Minute
	if m.work != nil {
		left = m.work.left(time.Now())
	}
	switch {
	case left <= 5*time.Second:
		return "Setting up your secure access… almost done."
	case left > 90*time.Second:
		return fmt.Sprintf("Setting up your secure access… about %d minutes left.", int((left+59*time.Second)/time.Minute))
	}
	secs := int((left + 9*time.Second) / (10 * time.Second) * 10)
	return fmt.Sprintf("Setting up your secure access… about %d seconds left.", secs)
}

// holds says whether r holds a place on the server, with the server's rule (docs/apps/seal.md
// section 5, "Places"): until it is read or taken, its secret's time ends unread, or 7 days pass with
// no send. Without news from the server a code older than 7 days is taken as free (if it is not, the
// server says so and Seal works for a place).
func (m *model) holds(r *Request) bool {
	if r.Outcome != "" || r.Unregistered {
		return false
	}
	if rm := m.remote[r]; rm != nil && rm.state == "arrived" {
		return rm.readBy.After(m.now())
	}
	return m.now().Sub(r.Created) < phase1
}

// taken counts the places of the key that hold a code.
func (m *model) taken() int {
	n := 0
	for _, r := range m.store.Requests {
		if r.Keyed && m.holds(r) {
			n++
		}
	}
	return n
}

// waitingToGo counts the requests confirmed by Gino and not on the server yet.
func (m *model) waitingToGo() int {
	n := 0
	for _, r := range m.store.Requests {
		if r.Outcome == "" && r.Unregistered {
			n++
		}
	}
	return n
}

// activeCount is what the limit of 5 counts: the codes waiting or arrived, and those still to go.
func (m *model) activeCount() int {
	n := m.waitingToGo()
	for _, r := range m.store.Requests {
		if m.holds(r) {
			n++
		}
	}
	return n
}

// placesWanted is how many places Gino's codes need: those on the server, those still to go, and the
// one on the codes screen.
func (m *model) placesWanted() int {
	n := m.taken() + m.waitingToGo()
	if m.made != nil {
		n++
	}
	return min(n, maxActive)
}

// codesReady says whether the request on the codes screen can go to the server at the confirm.
func (m *model) codesReady() bool {
	return m.access.Key != "" && m.work == nil && m.access.Places >= m.placesWanted()
}

// prepare starts the work that is missing, if none runs: the key, or a further place.
func (m *model) prepare() {
	if m.work != nil || m.workErr != "" {
		return
	}
	switch {
	case m.access.Key == "":
		m.startWork(workKey)
	case m.access.Places < m.placesWanted():
		m.startWork(workPlace)
	}
}

// startWork asks the server for a challenge and solves it away from the user interface.
func (m *model) startWork(kind string) {
	w := &work{kind: kind, started: time.Now()}
	m.work, m.workErr = w, ""
	key := m.access.key()
	m.async(func() {
		var newKey []byte
		places := 0
		ch, err := m.srv.challenge(kind)
		if err == nil {
			w.difficulty.Store(ch.Difficulty)
			subject := "key"
			if kind == workPlace {
				subject = b64(key)
			}
			nonce, ok := powSearch(ch.Challenge, subject, ch.Difficulty, &w.tries, func() { m.ui(func() {}) }, &w.stop)
			switch {
			case !ok:
				err = errStopped
			case kind == workKey:
				newKey, err = m.srv.newKey(ch.Challenge, nonce)
				places = 1
			default:
				places, err = m.srv.addPlace(key, ch.Challenge, nonce)
			}
		}
		m.ui(func() { m.workDone(w, newKey, places, err) })
	})
}

var errStopped = errors.New("stopped")

// workDone records the end of a work, then goes on with whatever waited for it.
func (m *model) workDone(w *work, newKey []byte, places int, err error) {
	if m.work != w {
		return
	}
	m.work = nil
	switch {
	case errors.Is(err, errStopped):
		return
	case err == nil && w.kind == workKey:
		m.access.Key, m.access.Places = b64(newKey), places
	case err == nil:
		m.access.Places = places
	case errors.Is(err, errUnknownKey): // purged while working for a place
		m.access.forget()
	case errors.Is(err, errMaxPlaces):
		m.access.Places = maxActive
	default:
		m.workErr = "could not reach the server"
		if !errors.Is(err, errServerBusy) && !errors.Is(err, errChallenge) && !isNetwork(err) {
			m.workErr = "the server answered " + err.Error()
		}
		m.later(15*time.Second, m.retryWork)
		return
	}
	m.saveAccess()
	m.prepare()
	m.registerPending()
}

// retryWork tries again after a failed work.
func (m *model) retryWork() {
	m.workErr = ""
	m.prepare()
	m.registerPending()
}

// stopPlaceWork stops the work for a further place that is no longer needed (Gino cancelled).
func (m *model) stopPlaceWork() {
	if m.work != nil && m.work.kind == workPlace && m.access.Places >= m.placesWanted() {
		m.work.stop.Store(true)
		m.work = nil
	}
}

// checkKey asks the server, in the background, whether it still knows the key (when Gino presses 1
// or Mario 2): unknown → a new key, at once, while they paste and type. Decided in section 5.
func (m *model) checkKey() {
	if m.access.Key == "" || m.work != nil {
		m.prepare()
		return
	}
	key := m.access.Key
	m.async(func() {
		places, err := m.srv.checkKey(m.access.key())
		m.ui(func() {
			if m.access.Key != key {
				return
			}
			switch {
			case errors.Is(err, errUnknownKey):
				m.access.forget()
				m.saveAccess()
			case err == nil && places != m.access.Places:
				m.access.Places = places
				m.saveAccess()
			}
			m.prepare()
		})
	})
}

func (m *model) saveAccess() {
	if err := m.access.save(); err != nil {
		m.workErr = "could not save the key (" + err.Error() + ")"
	}
}

// isNetwork says whether err is the connection, not an answer of the server.
func isNetwork(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "could not reach the server")
}

package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/trimlet/gui"
)

// fakeServer behaves like trimletseal-server (docs/apps/seal.md, "The server API"), in memory.
type fakeServer struct {
	codes   map[string]*fakeCode
	offline bool
	now     func() time.Time
	// loseAnswer: the next fetch delivers, then the answer is lost on the way;
	// cutAfter: and the connection stays down after that.
	loseAnswer, cutAfter bool
	full                 bool // new codes are refused
	challenges           int
	keys                 map[string]int // access key (base64) → places
	newKeys              int            // keys given out
	keyWorkAsked         int            // challenges for a key or a place
}

type fakeCode struct {
	ticketHash  []byte
	sealed      []byte
	hours       int
	sent        bool
	readBy      time.Time
	deliveredAt time.Time
	expired     bool   // phase 1 or 2 over (the tests set it)
	key         string // the access key that made it
}

func newFakeServer() *fakeServer {
	return &fakeServer{codes: map[string]*fakeCode{}, keys: map[string]int{}, now: time.Now}
}

var errOffline = errors.New("could not reach the server (offline)")

func (f *fakeServer) challenge(kind string) (challenge, error) {
	if f.offline {
		return challenge{}, errOffline
	}
	f.challenges++
	if kind != workCode {
		f.keyWorkAsked++
	}
	return challenge{Challenge: []byte{byte(f.challenges)}, Difficulty: 1}, nil
}

func (f *fakeServer) newKey(ch []byte, nonce uint64) ([]byte, error) {
	if f.offline {
		return nil, errOffline
	}
	if !powMeets(powWork(ch, "key", nonce), 1) {
		return nil, errors.New("wrong_work")
	}
	f.newKeys++
	key := bytes.Repeat([]byte{byte(f.newKeys)}, 32)
	f.keys[b64(key)] = 1
	return key, nil
}

func (f *fakeServer) addPlace(key, ch []byte, nonce uint64) (int, error) {
	if f.offline {
		return 0, errOffline
	}
	places, ok := f.keys[b64(key)]
	switch {
	case !ok:
		return 0, errUnknownKey
	case !powMeets(powWork(ch, b64(key), nonce), 1):
		return 0, errors.New("wrong_work")
	case places >= maxActive:
		return 0, errMaxPlaces
	}
	f.keys[b64(key)] = places + 1
	return places + 1, nil
}

func (f *fakeServer) checkKey(key []byte) (int, error) {
	if f.offline {
		return 0, errOffline
	}
	places, ok := f.keys[b64(key)]
	if !ok {
		return 0, errUnknownKey
	}
	return places, nil
}

// purge forgets a key and its codes, as the purge command does.
func (f *fakeServer) purge(key string) {
	delete(f.keys, key)
	for code, c := range f.codes {
		if c.key == key {
			delete(f.codes, code)
		}
	}
}

// holding counts the codes of key that hold a place.
func (f *fakeServer) holding(key string) int {
	n := 0
	for _, c := range f.codes {
		if c.key == key && c.deliveredAt.IsZero() && !c.expired {
			n++
		}
	}
	return n
}

func (f *fakeServer) register(key []byte, code string, ticketHash, ch []byte, nonce uint64) error {
	if f.offline {
		return errOffline
	}
	if !powMeets(powWork(ch, code, nonce), 1) {
		return errors.New("wrong_work")
	}
	if f.full {
		return errServerFull
	}
	places, ok := f.keys[b64(key)]
	if !ok {
		return errUnknownKey
	}
	if f.holding(b64(key)) >= places {
		return errNoPlace
	}
	if f.codes[code] != nil {
		return errCodeExists
	}
	f.codes[code] = &fakeCode{ticketHash: ticketHash, key: b64(key)}
	return nil
}

func (f *fakeServer) send(key []byte, code string, ticket, sealed []byte, hours int) (time.Time, error) {
	if f.offline {
		return time.Time{}, errOffline
	}
	if _, ok := f.keys[b64(key)]; !ok {
		return time.Time{}, errUnknownKey
	}
	c := f.codes[code]
	if c == nil {
		return time.Time{}, errNotFound
	}
	h := sha256.Sum256(ticket)
	if !bytes.Equal(h[:], c.ticketHash) {
		return time.Time{}, errWrongTicket
	}
	if c.sent {
		return time.Time{}, errAlreadySent
	}
	c.sealed, c.hours, c.sent = sealed, hours, true
	c.readBy = f.now().Add(time.Duration(hours) * time.Hour)
	return c.readBy, nil
}

func (f *fakeServer) state(code string, ticket []byte) (remoteState, error) {
	if f.offline {
		return remoteState{}, errOffline
	}
	c := f.codes[code]
	if c == nil || (c.expired && !c.sent) {
		return remoteState{}, errNotFound
	}
	h := sha256.Sum256(ticket)
	if !bytes.Equal(h[:], c.ticketHash) {
		return remoteState{}, errWrongTicket
	}
	switch {
	case !c.deliveredAt.IsZero():
		return remoteState{State: "delivered", DeliveredAt: c.deliveredAt}, nil
	case !c.sent:
		return remoteState{State: "waiting"}, nil
	case c.expired:
		c.sealed = nil
		return remoteState{State: "expired"}, nil
	}
	return remoteState{State: "arrived", ReadBy: c.readBy}, nil
}

func (f *fakeServer) fetch(code string, ticket []byte) ([]byte, error) {
	st, err := f.state(code, ticket)
	if err != nil {
		return nil, err
	}
	if st.State != "arrived" {
		return nil, &notArrived{st}
	}
	c := f.codes[code]
	sealed := c.sealed
	c.sealed, c.deliveredAt = nil, f.now()
	if f.loseAnswer {
		f.loseAnswer, f.offline = false, f.cutAfter
		return nil, errors.New("could not reach the server (connection reset)")
	}
	return sealed, nil
}

// makeCode makes a code as Gino, confirms it, and returns it.
func makeCode(t *testing.T, m *model, name string) *Request {
	t.Helper()
	m.Rune('1')
	typeText(m, name)
	m.Key(gui.KeyEnter)
	if m.screen != screenCodes {
		t.Fatalf("no codes screen:\n%s", screenText(m))
	}
	r := m.made
	m.Key(gui.KeyEnter)
	if m.dialog == nil || !strings.Contains(screenText(m), "Did you copy both codes?") {
		t.Fatalf("no confirmation:\n%s", screenText(m))
	}
	m.Rune('y')
	return r
}

// fillSend answers Mario's three questions.
func fillSend(m *model, code, unlock, secret string) {
	m.Rune('2')
	m.Paste(code)
	m.Key(gui.KeyEnter)
	m.Paste(unlock)
	m.Key(gui.KeyEnter)
	typeText(m, secret)
	m.Key(gui.KeyEnter)
}

func TestRegisterOnTheServer(t *testing.T) {
	m, _ := testModel(t)
	r := makeCode(t, m, "Mario allarme")
	fs := m.srv.(*fakeServer)
	c := fs.codes[plain(r.Code)]
	if c == nil {
		t.Fatal("the code was not registered")
	}
	pub, _ := decode32(r.Code, keyLen)
	ticket, _, _ := unlockKeys(r.Unlock, pub)
	if !bytes.Equal(c.ticketHash, ticketHash(ticket)) {
		t.Fatal("the server got the wrong ticket hash")
	}

	// Server unreachable at the confirm (the place was got before): the request is kept and goes
	// when the server answers.
	m.Rune('1')
	typeText(m, "Peppe wifi")
	m.Key(gui.KeyEnter)
	p := m.made
	fs.offline = true
	m.Key(gui.KeyEnter)
	m.Rune('y')
	if !strings.Contains(screenText(m), "? could not reach the server — will try again") || fs.codes[plain(p.Code)] != nil {
		t.Fatalf("offline:\n%s", screenText(m))
	}
	fs.offline = false
	m.toList()
	if fs.codes[plain(p.Code)] == nil || p.Unregistered || !p.Keyed {
		t.Fatalf("not registered when back online:\n%s", screenText(m))
	}
}

func TestSendAndOpen(t *testing.T) {
	m, _ := testModel(t)
	r := makeCode(t, m, "Mario allarme")

	// Mario pastes the unlock code in lower case and without dashes: it is the same code.
	fillSend(m, r.Code, strings.ToLower(strings.ReplaceAll(r.Unlock, "-", "")), "12345")
	if m.screen != screenTime || !strings.Contains(screenText(m), "[24 hours]") {
		t.Fatalf("time screen:\n%s", screenText(m))
	}
	m.Key(gui.KeyLeft)
	if !strings.Contains(screenText(m), "[2 hours]") {
		t.Fatal("← did not choose 2 hours")
	}
	m.Key(gui.KeyEnter)
	if m.dialog == nil || !strings.Contains(screenText(m), "This code takes only one secret") {
		t.Fatalf("no confirmation:\n%s", screenText(m))
	}
	// No: the secret again, to fix it.
	m.Rune('n')
	if m.screen != screenForm {
		t.Fatal("No did not go back to the secret")
	}
	m.Key(gui.KeyBackspace) // clears the proposed value
	typeText(m, "54321")
	m.Key(gui.KeyEnter)
	m.Key(gui.KeyEnter)
	m.Key(gui.KeyEnter) // Yes is chosen
	if m.screen != screenResult || !strings.Contains(screenText(m), "✔ Sent.") {
		t.Fatalf("not sent:\n%s", screenText(m))
	}
	if m.sendSecret != "" || m.sendUnlock != "" {
		t.Fatal("the secret is still in memory after sending")
	}

	// What the server holds opens only with Gino's private key and the unlock code.
	c := m.srv.(*fakeServer).codes[plain(r.Code)]
	if c.hours != 2 || len(c.sealed) != sealedLen {
		t.Fatalf("server holds %d hours, %d bytes", c.hours, len(c.sealed))
	}
	raw, _ := base64.StdEncoding.DecodeString(r.Key)
	priv, _ := ecdh.X25519().NewPrivateKey(raw)
	pub, _ := decode32(r.Code, keyLen)
	_, k, _ := unlockKeys(r.Unlock, pub)
	if got, err := open(c.sealed, priv, k); err != nil || string(got) != "54321" {
		t.Fatalf("opened %q, %v", got, err)
	}

	// Only one send per code.
	m.Key(gui.KeyEsc)
	fillSend(m, r.Code, r.Unlock, "again")
	m.Key(gui.KeyEnter)
	m.Key(gui.KeyEnter)
	if !strings.Contains(screenText(m), "already sent") {
		t.Fatalf("second send:\n%s", screenText(m))
	}
}

func TestSendErrors(t *testing.T) {
	m, _ := testModel(t)
	r := makeCode(t, m, "Mario allarme")
	other, _ := newUnlockCode()

	// The fields swapped, or not codes at all, are told at once.
	m.Rune('2')
	m.Paste(r.Unlock)
	m.Key(gui.KeyEnter)
	if !strings.Contains(screenText(m), "This is the unlock code") {
		t.Fatalf("unlock code in the code field:\n%s", screenText(m))
	}
	for range r.Unlock {
		m.Key(gui.KeyBackspace)
	}
	m.Paste(r.Code)
	m.Key(gui.KeyEnter)
	m.Paste(r.Code)
	m.Key(gui.KeyEnter)
	if !strings.Contains(screenText(m), "This is the code") {
		t.Fatalf("code in the unlock field:\n%s", screenText(m))
	}
	m.Key(gui.KeyEsc)

	// A secret over 4 KB.
	fillSend(m, r.Code, r.Unlock, "")
	m.Paste(strings.Repeat("x", maxSecret+1))
	m.Key(gui.KeyEnter)
	if !strings.Contains(screenText(m), "Too long") {
		t.Fatalf("long secret:\n%s", screenText(m))
	}
	m.Key(gui.KeyEsc)

	// A wrong unlock code: refused by the server, nothing sent.
	fillSend(m, r.Code, other, "12345")
	m.Key(gui.KeyEnter)
	m.Key(gui.KeyEnter)
	if !strings.Contains(screenText(m), "The unlock code does not match this code") {
		t.Fatalf("wrong unlock code:\n%s", screenText(m))
	}
	if m.srv.(*fakeServer).codes[plain(r.Code)].sealed != nil {
		t.Fatal("a send with the wrong ticket was kept")
	}
	m.Key(gui.KeyEsc)

	// An unknown (or expired) code.
	code2, _, _ := newKeys()
	fillSend(m, code2, r.Unlock, "12345")
	m.Key(gui.KeyEnter)
	m.Key(gui.KeyEnter)
	if !strings.Contains(screenText(m), "This code is not on the server yet, or it has expired.") ||
		!strings.Contains(screenText(m), "Try again in a few minutes. If it still fails, ask the receiver for a new code.") {
		t.Fatalf("unknown code:\n%s", screenText(m))
	}
	m.Key(gui.KeyEsc)

	// The server cannot be reached: enter tries again with the same secret.
	fs := m.srv.(*fakeServer)
	fs.offline = true
	fillSend(m, r.Code, r.Unlock, "12345")
	m.Key(gui.KeyEnter)
	m.Key(gui.KeyEnter)
	if !strings.Contains(screenText(m), "Not sent") || !strings.Contains(screenText(m), "enter try again") {
		t.Fatalf("offline:\n%s", screenText(m))
	}
	fs.offline = false
	m.Key(gui.KeyEnter)
	if !strings.Contains(screenText(m), "✔ Sent.") {
		t.Fatalf("retry:\n%s", screenText(m))
	}
}

// TestRealServer runs against a trimletseal-server, only if TRIMLETSEAL_SERVER is set
// (e.g. TRIMLETSEAL_SERVER=http://127.0.0.1:8688 go test ./cmd/seal -run Real).
func TestRealServer(t *testing.T) {
	if os.Getenv("TRIMLETSEAL_SERVER") == "" {
		t.Skip("TRIMLETSEAL_SERVER not set")
	}
	m, _ := testModel(t)
	m.srv = newHTTPServer()
	r := makeCode(t, m, "real")
	unlock := r.Unlock // the app deletes it after reading
	other, _ := newUnlockCode()
	fillSend(m, r.Code, other, "12345")
	m.Key(gui.KeyEnter)
	m.Key(gui.KeyEnter)
	if !strings.Contains(screenText(m), "does not match") {
		t.Fatalf("wrong unlock code:\n%s", screenText(m))
	}
	m.Key(gui.KeyEsc)
	fillSend(m, r.Code, r.Unlock, "12345")
	m.Key(gui.KeyEnter)
	m.Key(gui.KeyEnter)
	if !strings.Contains(screenText(m), "✔ Sent.") {
		t.Fatalf("send:\n%s", screenText(m))
	}
	m.Key(gui.KeyEsc)
	if !strings.Contains(screenText(m), "✔ arrived") {
		t.Fatalf("not arrived:\n%s", screenText(m))
	}
	m.cursor = 0
	m.Key(gui.KeyEnter)
	if !strings.Contains(screenText(m), "12345") {
		t.Fatalf("not read:\n%s", screenText(m))
	}
	m.Key(gui.KeyEsc)
	if !strings.Contains(screenText(m), "read on this device") {
		t.Fatalf("no receipt:\n%s", screenText(m))
	}
	fillSend(m, r.Code, unlock, "again")
	m.Key(gui.KeyEnter)
	m.Key(gui.KeyEnter)
	if !strings.Contains(screenText(m), "already sent") {
		t.Fatalf("second send:\n%s", screenText(m))
	}
	m.Key(gui.KeyEsc)
	code2, _, _ := newKeys()
	fillSend(m, code2, unlock, "12345")
	m.Key(gui.KeyEnter)
	m.Key(gui.KeyEnter)
	if !strings.Contains(screenText(m), "not on the server yet, or it has expired") {
		t.Fatalf("unknown code:\n%s", screenText(m))
	}
}

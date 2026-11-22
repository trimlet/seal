package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trimlet/gui"
)

// Blocks 5 and 5b: the app's side of the server's defences, and the access key.

func TestServerFull(t *testing.T) {
	m, _ := testModel(t)
	m.srv.(*fakeServer).full = true
	makeCode(t, m, "Mario allarme")
	if !strings.Contains(screenText(m), "✖ the server is full — this code will not work. Make a new one later.") {
		t.Fatalf("full:\n%s", screenText(m))
	}
}

func TestPowSolves(t *testing.T) {
	ch := []byte("a challenge")
	code := strings.Repeat("Q", codeLen)
	n := powSolve(ch, code, 16)
	if !powMeets(powWork(ch, code, n), 16) {
		t.Fatal("the solution does not meet the difficulty")
	}
}

// waitingModel is a model whose long work does not end by itself: f runs it when the test says.
func waitingModel(t *testing.T) (*model, *[]func()) {
	m, _ := testModel(t)
	var held []func()
	m.async = func(f func()) { held = append(held, f) }
	return m, &held
}

// runHeld runs the work held so far (and what it starts in turn).
func runHeld(m *model, held *[]func()) {
	for len(*held) > 0 {
		f := (*held)[0]
		*held = (*held)[1:]
		f()
	}
}

func TestGinoWaitsForTheKeyOnTheCodesScreen(t *testing.T) {
	m, held := waitingModel(t)
	m.start() // the first opening: the work for the key starts
	if m.work == nil || m.work.kind != workKey {
		t.Fatal("no work for the key at the first opening")
	}
	m.Rune('1')
	typeText(m, "Mario allarme")
	m.Key(gui.KeyEnter)
	(*held)[len(*held)-1]() // only the making of the code (Argon2id), not the key
	*held = (*held)[:len(*held)-1]
	text := screenText(m)
	if m.screen != screenCodes || !strings.Contains(text, "Setting up your secure access… about 2 minutes left.") ||
		strings.Contains(text, "enter done") || !strings.Contains(text, "esc cancel") {
		t.Fatalf("codes screen while waiting:\n%s", text)
	}
	m.Rune('c') // copying works
	m.Key(gui.KeyEnter)
	if m.dialog != nil {
		t.Fatal("Enter opened the confirmation before the key")
	}
	runHeld(m, held) // the key is ready
	text = screenText(m)
	if strings.Contains(text, "Setting up") || !strings.Contains(text, "enter done · esc cancel") {
		t.Fatalf("codes screen with the key:\n%s", text)
	}
	m.Key(gui.KeyEnter)
	m.Rune('y')
	runHeld(m, held)
	if !strings.Contains(screenText(m), "waiting…") || m.srv.(*fakeServer).codes[plain(m.store.Requests[0].Code)] == nil {
		t.Fatalf("not registered:\n%s", screenText(m))
	}
	path := accessPath(m.store.path)
	if a, err := loadAccess(path); err != nil || a.Key == "" || a.Places != 1 {
		t.Fatalf("access.json: %+v, %v", a, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 || filepath.Dir(path) != filepath.Dir(m.store.path) {
		t.Fatalf("access.json: %v %v", info, err)
	}
}

func TestCancelLeavesNothing(t *testing.T) {
	m, path := testModel(t)
	m.Rune('1')
	typeText(m, "Mario allarme")
	m.Key(gui.KeyEnter)
	code := m.made.Code
	m.Key(gui.KeyEsc)
	if m.dialog == nil || !strings.Contains(screenText(m), "Cancel this code?") {
		t.Fatalf("no cancel window:\n%s", screenText(m))
	}
	m.Rune('n') // No: back on the codes
	if m.screen != screenCodes || m.made == nil {
		t.Fatal("No left the codes screen")
	}
	m.Key(gui.KeyEsc)
	m.Key(gui.KeyEnter) // Yes is chosen
	if m.screen != screenList || len(m.store.Requests) != 0 || m.srv.(*fakeServer).codes[plain(code)] != nil {
		t.Fatalf("after cancel:\n%s", screenText(m))
	}
	if data, _ := readFile(path); strings.Contains(data, code) {
		t.Fatal("a cancelled code is in pending.json")
	}
}

func TestPlaces(t *testing.T) {
	m, _ := testModel(t)
	fs := m.srv.(*fakeServer)
	a := makeCode(t, m, "Mario allarme")
	if m.access.Places != 1 || fs.keyWorkAsked != 1 {
		t.Fatalf("first code: %d places, %d works", m.access.Places, fs.keyWorkAsked)
	}
	// A second one while the first waits: the work for a further place.
	makeCode(t, m, "Peppe wifi")
	if m.access.Places != 2 || fs.keyWorkAsked != 2 {
		t.Fatalf("second code: %d places, %d works", m.access.Places, fs.keyWorkAsked)
	}
	// The first is read: its place frees, the next code needs no work.
	sendTo(t, m, a, "12345")
	m.cursor = 0
	m.Key(gui.KeyEnter)
	m.Key(gui.KeyEsc)
	makeCode(t, m, "Luca wifi")
	if m.access.Places != 2 || fs.keyWorkAsked != 2 {
		t.Fatalf("after a read: %d places, %d works", m.access.Places, fs.keyWorkAsked)
	}
}

func TestMarioWaitsForTheKeyOnTheTimeScreen(t *testing.T) {
	m, held := waitingModel(t)
	m.start()
	code, _, _ := newKeys()
	unlock, _ := newUnlockCode()
	fillSend(m, code, unlock, "12345")
	text := screenText(m)
	if m.screen != screenTime || !strings.Contains(text, "Setting up your secure access…") || strings.Contains(text, "enter send") {
		t.Fatalf("time screen while waiting:\n%s", text)
	}
	m.Key(gui.KeyEnter)
	if m.dialog != nil {
		t.Fatal("Enter opened the confirmation before the key")
	}
	runHeld(m, held)
	if strings.Contains(screenText(m), "Setting up") || !strings.Contains(screenText(m), "enter send") {
		t.Fatalf("time screen with the key:\n%s", screenText(m))
	}
	m.Key(gui.KeyEnter)
	if m.dialog == nil {
		t.Fatal("no confirmation with the key")
	}
}

func TestPurgedKeyIsReplaced(t *testing.T) {
	m, _ := testModel(t)
	fs := m.srv.(*fakeServer)
	r := makeCode(t, m, "Mario allarme")
	old := m.access.Key
	fs.purge(old) // an attack: the purge takes this key and its codes
	// Mario presses 2: Seal sees the key is gone and makes a new one.
	fillSend(m, r.Code, r.Unlock, "12345")
	if m.access.Key == "" || m.access.Key == old || fs.newKeys != 2 {
		t.Fatalf("key after the purge: %q (old %q), %d keys", m.access.Key, old, fs.newKeys)
	}
	m.Key(gui.KeyEsc)
	// The key purged after the check: the registration of a code makes a new one and goes on.
	fs.purge(m.access.Key)
	p := makeCode(t, m, "Peppe wifi")
	if fs.codes[plain(p.Code)] == nil || fs.newKeys != 3 {
		t.Fatalf("not registered with a new key:\n%s", screenText(m))
	}
}

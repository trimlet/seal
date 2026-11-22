package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/trimlet/gui"
)

func TestBase32RoundTrip(t *testing.T) {
	b := make([]byte, keyLen)
	for i := range b {
		b[i] = byte(i*37 + 11)
	}
	s := encode32(b)
	if len(s) != codeLen {
		t.Fatalf("length %d, want %d", len(s), codeLen)
	}
	back, err := decode32(group(s), keyLen)
	if err != nil || string(back) != string(b) {
		t.Fatalf("round trip failed: %v", err)
	}
	// Case, dashes, spaces and the look-alike letters are ignored.
	messy := strings.ToLower(group(s))
	messy = strings.ReplaceAll(messy, "1", "l")
	messy = strings.ReplaceAll(messy, "0", "o")
	if back, err := decode32(" "+messy+"\n", keyLen); err != nil || string(back) != string(b) {
		t.Fatalf("messy round trip failed: %v", err)
	}
	if _, err := decode32(s[:codeLen-1], keyLen); err == nil {
		t.Fatal("a short code was accepted")
	}
	if _, err := decode32("U"+s[1:], keyLen); err == nil {
		t.Fatal("U was accepted")
	}
}

func TestNewCodes(t *testing.T) {
	code, key, err := newKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != codeLen+codeLen/4-1 {
		t.Fatalf("code %q: length %d", code, len(code))
	}
	// The code is the public key of the private key kept.
	raw, _ := base64.StdEncoding.DecodeString(key)
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := decode32(code, keyLen)
	if string(priv.PublicKey().Bytes()) != string(pub) {
		t.Fatal("the code is not the public key")
	}

	unlock, err := newUnlockCode()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$`).MatchString(unlock) {
		t.Fatalf("unlock code %q", unlock)
	}
	other, _ := newUnlockCode()
	if other == unlock {
		t.Fatal("two unlock codes are the same")
	}
}

func testModel(t *testing.T) (*model, string) {
	path := filepath.Join(t.TempDir(), "trimletseal", "pending.json")
	s, err := loadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	fs := newFakeServer()
	m := newModel(s, fs)
	m.access = &Access{path: accessPath(path)}
	m.now = func() time.Time { return time.Date(2026, 11, 21, 10, 14, 0, 0, time.Local) }
	fs.now = func() time.Time { return m.now() }
	m.async = func(f func()) { f() }
	return m, path
}

func typeText(m *model, s string) {
	for _, r := range s {
		m.Rune(r)
	}
}

func screenText(m *model) string {
	var b strings.Builder
	for _, l := range m.Render(120, 30) {
		for _, s := range l {
			b.WriteString(s.Text)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func TestReceiveMakesARequest(t *testing.T) {
	m, path := testModel(t)
	var copied string
	m.copy = func(s string) { copied = s }

	m.Rune('1')
	if m.screen != screenForm || !strings.Contains(screenText(m), "Name this code (only you will see it):") {
		t.Fatalf("the name is not asked:\n%s", screenText(m))
	}
	m.Key(gui.KeyEnter) // empty name
	if m.screen != screenForm {
		t.Fatal("an empty name was accepted")
	}
	typeText(m, "Mario allarme")
	m.Key(gui.KeyEnter)
	if m.screen != screenCodes {
		t.Fatalf("screen %d after the name", m.screen)
	}
	r := m.made
	text := screenText(m)
	for _, want := range []string{"two different channels", r.Code, r.Unlock} {
		if !strings.Contains(text, want) {
			t.Fatalf("%q not on the screen:\n%s", want, text)
		}
	}
	m.Rune('c')
	if copied != r.Code {
		t.Fatalf("c copied %q", copied)
	}
	m.Rune('u')
	if copied != r.Unlock {
		t.Fatalf("u copied %q", copied)
	}
	// Nothing written before Gino's Yes.
	if _, err := os.Stat(path); err == nil {
		t.Fatal("pending.json written before the confirm")
	}
	m.Key(gui.KeyEnter)
	m.Rune('y')
	if m.screen != screenList || !strings.Contains(screenText(m), "Mario allarme") || !strings.Contains(screenText(m), "waiting…") {
		t.Fatalf("the list does not show the request:\n%s", screenText(m))
	}

	// Closed and opened again: the request is still there, with the same codes.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("pending.json mode %v", info.Mode().Perm())
	}
	s, err := loadStore(path)
	if err != nil || len(s.Requests) != 1 {
		t.Fatalf("reopened: %v, %d requests", err, len(s.Requests))
	}
	got := s.Requests[0]
	if got.Name != "Mario allarme" || got.Code != r.Code || got.Key != r.Key || got.Unlock != r.Unlock || !got.Created.Equal(r.Created) {
		t.Fatalf("reopened request differs: %+v", got)
	}
}

func TestEscCancelsTheName(t *testing.T) {
	m, _ := testModel(t)
	m.Rune('1')
	typeText(m, "Peppe")
	m.Key(gui.KeyEsc)
	if m.screen != screenList || len(m.store.Requests) != 0 {
		t.Fatal("esc did not cancel")
	}
}

func TestAtMostFiveWaiting(t *testing.T) {
	m, _ := testModel(t)
	for i := 0; i < maxActive; i++ {
		makeCode(t, m, "code")
	}
	m.Rune('1')
	if m.screen != screenList || !strings.Contains(screenText(m), "5 codes waiting") {
		t.Fatalf("a sixth code was allowed:\n%s", screenText(m))
	}
	// After 7 days with nothing sent they no longer hold a place.
	m.now = func() time.Time { return time.Date(2026, 11, 28, 10, 15, 0, 0, time.Local) }
	m.Rune('1')
	if m.screen != screenForm {
		t.Fatal("expired codes still count")
	}
}

func TestEscAsksBeforeQuitting(t *testing.T) {
	m, _ := testModel(t)
	quit := false
	m.quit = func() { quit = true }
	m.Key(gui.KeyEsc)
	if m.dialog == nil || !strings.Contains(screenText(m), "Quit Trimlet Seal?") {
		t.Fatal("no quit window")
	}
	m.Key(gui.KeyEnter) // Yes is chosen
	if !quit {
		t.Fatal("did not quit")
	}
}

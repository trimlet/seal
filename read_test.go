package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/trimlet/gui"
)

// sendTo sends secret to r's code as Mario, then goes back to the list (which asks the server again).
func sendTo(t *testing.T, m *model, r *Request, secret string) {
	t.Helper()
	fillSend(m, r.Code, r.Unlock, secret)
	m.Key(gui.KeyEnter)
	m.Key(gui.KeyEnter)
	if !strings.Contains(screenText(m), "✔ Sent.") {
		t.Fatalf("not sent:\n%s", screenText(m))
	}
	m.Key(gui.KeyEsc)
}

func TestReadOnce(t *testing.T) {
	m, path := testModel(t)
	var copied string
	m.copy = func(s string) { copied = s }
	r := makeCode(t, m, "Mario allarme")
	if !strings.Contains(screenText(m), "waiting…") {
		t.Fatalf("not waiting:\n%s", screenText(m))
	}
	m.Key(gui.KeyEnter) // nothing to open yet
	if m.screen != screenList {
		t.Fatal("enter opened a waiting code")
	}

	sendTo(t, m, r, "12345")
	text := screenText(m)
	if !strings.Contains(text, "✔ arrived · 24 h left") || strings.Contains(text, "12345") {
		t.Fatalf("list after the send:\n%s", text)
	}
	key, unlock := r.Key, r.Unlock
	m.cursor = 0
	m.Key(gui.KeyEnter)
	if m.screen != screenSecret || !strings.Contains(screenText(m), "12345") || !strings.Contains(screenText(m), "deleted when you close") {
		t.Fatalf("secret screen:\n%s", screenText(m))
	}
	m.Rune('c')
	if copied != "12345" {
		t.Fatalf("copied %q", copied)
	}
	// The keys are gone from pending.json already, and the secret was never written there.
	data, _ := readFile(path)
	if strings.Contains(data, unlock) || strings.Contains(data, key) || strings.Contains(data, "12345") || !strings.Contains(data, `"outcome": "read"`) {
		t.Fatalf("pending.json after reading:\n%s", data)
	}
	m.Key(gui.KeyEsc)
	if m.secret != "" || !strings.Contains(screenText(m), "read on this device · Sat 21 Nov 10:14") {
		t.Fatalf("receipt:\n%s", screenText(m))
	}
	m.Key(gui.KeyEnter)
	if m.screen != screenList {
		t.Fatal("a read code opened again")
	}
	// The server delivered once.
	if c := m.srv.(*fakeServer).codes[plain(r.Code)]; c.sealed != nil || c.deliveredAt.IsZero() {
		t.Fatal("the server still holds the secret")
	}
}

func TestHowRequestsEnd(t *testing.T) {
	m, _ := testModel(t)
	fs := m.srv.(*fakeServer)
	none := makeCode(t, m, "nothing sent")
	late := makeCode(t, m, "not read")
	other := makeCode(t, m, "elsewhere")
	sendTo(t, m, late, "a")
	sendTo(t, m, other, "b")

	fs.codes[plain(none.Code)].expired = true
	fs.codes[plain(late.Code)].expired = true
	ticket, _ := m.ticketOf(other)
	if _, err := fs.fetch(plain(other.Code), ticket); err != nil { // someone with a copy of pending.json
		t.Fatal(err)
	}
	m.toList()
	text := screenText(m)
	for _, want := range []string{"✖ expired — nothing was sent.", "✖ expired — it arrived but was not read in time.", "✖ delivered elsewhere", "If it was not you, warn the sender."} {
		if !strings.Contains(text, want) {
			t.Fatalf("%q not in the list:\n%s", want, text)
		}
	}
	for _, r := range m.store.Requests {
		if r.Key != "" || r.Unlock != "" || r.Ticket != "" {
			t.Fatalf("%s kept its keys", r.Name)
		}
	}
}

func TestKeysAndRowsExpire(t *testing.T) {
	m, _ := testModel(t)
	r := makeCode(t, m, "old")
	read := makeCode(t, m, "read")
	sendTo(t, m, read, "x")
	m.cursor = 1
	m.Key(gui.KeyEnter)
	m.Key(gui.KeyEsc)

	// 6 days later the receipt is still there.
	start := m.now()
	m.now = func() time.Time { return start.Add(6 * 24 * time.Hour) }
	m.toList()
	if !strings.Contains(screenText(m), "read on this device") {
		t.Fatal("the receipt left too early")
	}
	// 8 days: the waiting one loses its key even without the server; the receipt (7 days) is gone.
	m.srv.(*fakeServer).offline = true
	m.now = func() time.Time { return start.Add(8 * 24 * time.Hour) }
	m.toList()
	if r.Key != "" || r.Outcome != outcomeLapsed {
		t.Fatalf("after 8 days: key %q, outcome %q", r.Key, r.Outcome)
	}
	if strings.Contains(screenText(m), "read on this device") {
		t.Fatal("the receipt stayed more than 7 days")
	}
}

func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	return string(b), err
}

package main

import (
	"strings"
	"testing"
	"time"

	"github.com/trimlet/gui"
)

// Block 4: when something goes wrong while Gino reads.

func TestNotReceived(t *testing.T) {
	m, _ := testModel(t)
	r := makeCode(t, m, "Mario allarme")
	sendTo(t, m, r, "12345")
	m.srv.(*fakeServer).loseAnswer = true
	m.cursor = 0
	m.Key(gui.KeyEnter)
	text := screenText(m)
	if !strings.Contains(text, "✖ Not received — the connection failed while it was arriving.") || !strings.Contains(text, "Ask the sender to send it again.") || strings.Contains(text, "12345") {
		t.Fatalf("not received:\n%s", text)
	}
	m.Key(gui.KeyEsc)
	if !strings.Contains(screenText(m), "✖ not received") || r.Key != "" {
		t.Fatalf("row:\n%s", screenText(m))
	}
}

// The answer is lost and the connection stays down: the app learns it later, from the times.
func TestNotReceivedLearnedLater(t *testing.T) {
	m, _ := testModel(t)
	r := makeCode(t, m, "Mario allarme")
	sendTo(t, m, r, "12345")
	fs := m.srv.(*fakeServer)
	fs.loseAnswer, fs.cutAfter = true, true
	m.cursor = 0
	m.Key(gui.KeyEnter)
	if !strings.Contains(screenText(m), "Try again") || r.Outcome != "" || len(r.Tries) != 1 {
		t.Fatalf("offline after the delivery:\n%s", screenText(m))
	}
	// An hour later, back online: the server delivered at the time of the try.
	fs.offline = false
	start := m.now()
	m.now = func() time.Time { return start.Add(time.Hour) }
	m.toList()
	if !strings.Contains(screenText(m), "✖ not received") {
		t.Fatalf("later:\n%s", screenText(m))
	}
}

// Someone with a copy of pending.json fetched an hour before Gino pressed Enter.
func TestDeliveredElsewhereOnEnter(t *testing.T) {
	m, _ := testModel(t)
	r := makeCode(t, m, "Mario allarme")
	sendTo(t, m, r, "12345")
	ticket, _ := m.ticketOf(r)
	if _, err := m.srv.fetch(plain(r.Code), ticket); err != nil {
		t.Fatal(err)
	}
	start := m.now()
	m.now = func() time.Time { return start.Add(time.Hour) }
	m.cursor = 0
	m.Key(gui.KeyEnter) // the row still says arrived: the list was not asked again
	text := screenText(m)
	if m.screen != screenList || !strings.Contains(text, "✖ delivered elsewhere · Sat 21 Nov 10:14 — not to this device.") {
		t.Fatalf("elsewhere:\n%s", text)
	}
}

// The server cannot be reached at all: nothing was delivered, Enter tries again later.
func TestServerUnreachableOnEnter(t *testing.T) {
	m, _ := testModel(t)
	r := makeCode(t, m, "Mario allarme")
	sendTo(t, m, r, "12345")
	fs := m.srv.(*fakeServer)
	fs.offline = true
	m.cursor = 0
	m.Key(gui.KeyEnter)
	if !strings.Contains(screenText(m), "Try again") || r.Outcome != "" {
		t.Fatalf("unreachable:\n%s", screenText(m))
	}
	fs.offline = false
	start := m.now()
	m.now = func() time.Time { return start.Add(time.Hour) }
	m.toList()
	m.Key(gui.KeyEnter)
	if !strings.Contains(screenText(m), "12345") {
		t.Fatalf("second Enter:\n%s", screenText(m))
	}
}

package main

import (
	"encoding/base64"
	"os"
	"testing"
)

// TestSteal plays the bad guy with a copy of pending.json, to try "delivered elsewhere" by hand
// (block 4): it reads the author's real pending.json and takes from the server the secret of the
// code named in TRIMLETSEAL_STEAL, without opening it and without changing the file.
//
//	TRIMLETSEAL_STEAL="prova furto" go test -run Steal -v ./cmd/seal
func TestSteal(t *testing.T) {
	name := os.Getenv("TRIMLETSEAL_STEAL")
	if name == "" {
		t.Skip("TRIMLETSEAL_STEAL not set")
	}
	path, err := storePath()
	if err != nil {
		t.Fatal(err)
	}
	s, err := loadStore(path) // the copy: read only, never saved
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range s.Requests {
		if r.Name != name || r.Outcome != "" {
			continue
		}
		ticket, err := base64.StdEncoding.DecodeString(r.Ticket)
		if err != nil || len(ticket) == 0 {
			t.Fatalf("no ticket for %q", name)
		}
		sealed, err := newHTTPServer().fetch(plain(r.Code), ticket)
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}
		t.Logf("took %d bytes for %q from the server", len(sealed), name)
		return
	}
	t.Fatalf("no active code named %q", name)
}

package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Request is one code Gino made (docs/design.md section 3d, pending.json). The secret itself is
// never written here. When the request ends (read, expired…) the keys are deleted and only the
// row stays, as a receipt, for a few days.
type Request struct {
	Name    string    `json:"name"`             // only Gino sees it, e.g. "Mario allarme"
	Code    string    `json:"code"`             // the public key, as sent: it travels outside anyway
	Key     string    `json:"key,omitempty"`    // the private key, base64 (in clear since the PIN was removed)
	Unlock  string    `json:"unlock,omitempty"` // the unlock code, needed again to open the secret
	Ticket  string    `json:"ticket,omitempty"` // base64, from the unlock code: asking the server needs no Argon2id
	Created time.Time `json:"created"`          // phase 1 lasts 7 days from here

	// Block 5b: a request is written here only after Gino's Yes to "Did you copy both codes?"; it may
	// still wait for the access key (or a place) before going to the server.
	Unregistered bool `json:"unregistered,omitempty"` // confirmed, not on the server yet
	Keyed        bool `json:"keyed,omitempty"`        // registered with the access key (holds one of its places)

	Tries   []time.Time `json:"tries,omitempty"`   // when Enter asked for the secret (to tell "not received")
	Outcome string      `json:"outcome,omitempty"` // how it ended (outcome… below); "" while active
	Ended   time.Time   `json:"ended,omitzero"`    // when: read, delivered elsewhere, expired
}

// How a request ends.
const (
	outcomeRead      = "read"         // read on this device
	outcomeExpired   = "expired"      // nothing was sent within 7 days
	outcomeNotRead   = "not_read"     // sent, not read in time
	outcomeElsewhere = "elsewhere"    // the server delivered it, not to this device
	outcomeNotRecv   = "not_received" // delivered while this device asked, but the answer never arrived
	outcomeBroken    = "broken"       // delivered here, but it could not be opened
	outcomeLapsed    = "lapsed"       // 8 days passed and the app never learned how it ended
	outcomeFull      = "full"         // the server was full: the code never went in
)

// How long the sender has to send (phase 1, decided: 7 days).
const phase1 = 7 * 24 * time.Hour

// After this the key is useless and deleted, read or not (decided: 8 days = 7 to send + 24 hours to read).
const keyLife = 8 * 24 * time.Hour

// How long an ended row stays in the list (decided for the receipt: 7 days).
const rowLife = 7 * 24 * time.Hour

// A delivery this close to one of this device's tries is that try, whose answer was lost: from a
// little before (the two clocks may differ) to a little after (the app waits at most 30 seconds).
const (
	tryBefore = 2 * time.Minute
	tryAfter  = 3 * time.Minute
)

// deliveredOutcome says, from the time the server delivered, whether it went to one of this
// device's tries (the connection failed while it was arriving) or elsewhere. A bad guy with a copy of
// pending.json cannot know when Gino will press Enter, so he cannot make the times coincide on purpose.
func (r *Request) deliveredOutcome(at time.Time) string {
	for _, t := range r.Tries {
		if at.After(t.Add(-tryBefore)) && at.Before(t.Add(tryAfter)) {
			return outcomeNotRecv
		}
	}
	return outcomeElsewhere
}

// How many requests may wait at once (decided: 5): the most places of an access key, checked by the
// server; the app says it before asking (docs/apps/seal.md section 5).
const maxActive = 5

// Store is everything Trimlet Seal keeps on this computer: the file pending.json.
type Store struct {
	Requests []*Request `json:"requests"`

	path string
}

// storePath is the file in the standard folder for app settings
// (~/Library/Application Support on Mac, %AppData% on Windows).
func storePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "trimletseal", "pending.json"), nil
}

// loadStore reads the file; a file that does not exist yet is an empty store.
func loadStore(path string) (*Store, error) {
	s := &Store{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, err
	}
	return s, nil
}

// save writes the file, readable only by the user, replacing it in one step.
func (s *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// end closes a request: its keys are deleted, the row stays as a receipt.
func (r *Request) end(outcome string, at time.Time) {
	r.Key, r.Unlock, r.Ticket, r.Tries = "", "", "", nil
	r.Outcome, r.Ended = outcome, at
}

// tidy deletes the keys of requests older than 8 days and the rows ended more than 7 days ago.
// It says whether anything changed.
func (s *Store) tidy(now time.Time) bool {
	changed := false
	kept := s.Requests[:0]
	for _, r := range s.Requests {
		if r.Outcome == "" && now.Sub(r.Created) >= keyLife {
			r.end(outcomeLapsed, r.Created.Add(keyLife))
			changed = true
		}
		if r.Outcome != "" && now.Sub(r.Ended) >= rowLife {
			changed = true
			continue
		}
		kept = append(kept, r)
	}
	s.Requests = kept
	return changed
}

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// serverURL is trimletseal-server, online since block 6 (2026-11-22): Caddy on the VPS sends
// vault.trimlet.dev/seal/* to it. TRIMLETSEAL_SERVER changes it (e.g. http://127.0.0.1:8688 for the
// server on this Mac, `cargo run -- serve`).
const serverURL = "https://vault.trimlet.dev/seal"

// The answers of the server that the app tells apart.
var (
	errServerFull  = errors.New("server_full")
	errServerBusy  = errors.New("server_busy")
	errChallenge   = errors.New("invalid_challenge")
	errCodeExists  = errors.New("code_exists")
	errNotFound    = errors.New("not_found")
	errWrongTicket = errors.New("wrong_ticket")
	errAlreadySent = errors.New("already_sent")
	errUnknownKey  = errors.New("unknown_key") // the access key was purged, or not used for a year
	errNoPlace     = errors.New("no_place")    // every place of the key holds a code
	errMaxPlaces   = errors.New("max_places")
)

// remoteState is where a code stands on the server: "waiting", "arrived" (to read by ReadBy),
// "expired" (sent, not read in time) or "delivered" (at DeliveredAt).
type remoteState struct {
	State       string    `json:"state"`
	ReadBy      time.Time `json:"read_by"`
	DeliveredAt time.Time `json:"delivered_at"`
}

// notArrived is the answer to a fetch when there is nothing to deliver, with the reason.
type notArrived struct{ st remoteState }

func (e *notArrived) Error() string { return "nothing to deliver (" + e.st.State + ")" }

// challenge is the server's request of work (block 5): for a new code, a new access key or a
// further place (block 5b).
type challenge struct {
	Challenge  []byte `json:"challenge"`
	Difficulty uint64 `json:"difficulty"`
}

// The kinds of work (the server sets how much each costs).
const (
	workCode  = "code"  // ≈1.5 s on the author's Mac, for every new code
	workKey   = "key"   // ≈2 minutes, for a new access key
	workPlace = "place" // ≈2 minutes, for each further place of the key
)

// server is what the app asks of trimletseal-server (a fake one in the tests).
type server interface {
	// challenge asks for the work of a kind (workCode, workKey, workPlace).
	challenge(kind string) (challenge, error)
	// newKey gets an access key with a solution of a workKey challenge (subject "key"); a key
	// starts with one place.
	newKey(challenge []byte, nonce uint64) (key []byte, err error)
	// addPlace gets one more place for key with a solution of a workPlace challenge (subject: the
	// key in base64); it returns the places now.
	addPlace(key, challenge []byte, nonce uint64) (places int, err error)
	// checkKey asks whether the server still knows key, and its places.
	checkKey(key []byte) (places int, err error)
	// register tells the server about a new code (52 characters, no dashes) and the hash of its
	// ticket, with the access key, and the challenge and the nonce that solves it.
	register(key []byte, code string, ticketHash, challenge []byte, nonce uint64) error
	// send gives the server the encrypted secret for a code, with the ticket and the sender's
	// access key; hours is 1, 2 or 24.
	send(key []byte, code string, ticket, sealed []byte, hours int) (readBy time.Time, err error)
	// state asks where a code stands ("is something there?").
	state(code string, ticket []byte) (remoteState, error)
	// fetch takes the secret: the server delivers it once and deletes it.
	fetch(code string, ticket []byte) ([]byte, error)
}

type httpServer struct {
	base   string
	client *http.Client
}

func newHTTPServer() *httpServer {
	base := serverURL
	if s := os.Getenv("TRIMLETSEAL_SERVER"); s != "" {
		base = strings.TrimRight(s, "/")
	}
	return &httpServer{base: base, client: &http.Client{Timeout: 30 * time.Second}}
}

// post sends body as JSON and reads the answer into out; an {"error": …} answer becomes an error.
func (s *httpServer) post(path string, body, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := s.client.Post(s.base+path, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("could not reach the server (%w)", err)
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("could not reach the server (%w)", err)
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(answer, &e)
		if e.Error == "not_arrived" {
			var st remoteState
			json.Unmarshal(answer, &st)
			return &notArrived{st}
		}
		for _, known := range []error{errServerFull, errServerBusy, errChallenge, errCodeExists, errNotFound, errWrongTicket, errAlreadySent, errUnknownKey, errNoPlace, errMaxPlaces} {
			if e.Error == known.Error() {
				return known
			}
		}
		if e.Error == "" {
			e.Error = resp.Status
		}
		return fmt.Errorf("the server answered %s", e.Error)
	}
	if out != nil {
		return json.Unmarshal(answer, out)
	}
	return nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func (s *httpServer) challenge(kind string) (challenge, error) {
	var c challenge // []byte fields are base64 in JSON
	err := s.post("/challenge", map[string]string{"kind": kind}, &c)
	return c, err
}

func (s *httpServer) newKey(challenge []byte, nonce uint64) ([]byte, error) {
	var out struct {
		Key []byte `json:"key"`
	}
	err := s.post("/keys", map[string]any{"challenge": b64(challenge), "nonce": nonce}, &out)
	return out.Key, err
}

type placesAnswer struct {
	Places int `json:"places"`
}

func (s *httpServer) addPlace(key, challenge []byte, nonce uint64) (int, error) {
	var out placesAnswer
	err := s.post("/keys/place", map[string]any{"key": b64(key), "challenge": b64(challenge), "nonce": nonce}, &out)
	return out.Places, err
}

func (s *httpServer) checkKey(key []byte) (int, error) {
	var out placesAnswer
	err := s.post("/keys/check", map[string]any{"key": b64(key)}, &out)
	return out.Places, err
}

func (s *httpServer) register(key []byte, code string, ticketHash, challenge []byte, nonce uint64) error {
	return s.post("/codes", map[string]any{"key": b64(key), "code": code, "ticket_hash": b64(ticketHash), "challenge": b64(challenge), "nonce": nonce}, nil)
}

func (s *httpServer) send(key []byte, code string, ticket, sealed []byte, hours int) (time.Time, error) {
	var out struct {
		ReadBy time.Time `json:"read_by"`
	}
	err := s.post("/send", map[string]any{"key": b64(key), "code": code, "ticket": b64(ticket), "secret": b64(sealed), "hours": hours}, &out)
	return out.ReadBy, err
}

func (s *httpServer) state(code string, ticket []byte) (remoteState, error) {
	var st remoteState
	err := s.post("/state", map[string]string{"code": code, "ticket": b64(ticket)}, &st)
	return st, err
}

func (s *httpServer) fetch(code string, ticket []byte) ([]byte, error) {
	var out struct {
		Secret string `json:"secret"`
	}
	if err := s.post("/fetch", map[string]string{"code": code, "ticket": b64(ticket)}, &out); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(out.Secret)
}

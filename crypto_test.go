package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"
)

func TestSealOpen(t *testing.T) {
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pub := priv.PublicKey().Bytes()
	unlock, _ := newUnlockCode()

	start := time.Now()
	ticket, k, err := unlockKeys(unlock, pub)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Argon2id took %v", time.Since(start))
	if bytes.Equal(ticket, k) {
		t.Fatal("ticket and k are the same")
	}
	// Mario pastes the unlock code in lower case, without dashes: same keys.
	ticket2, k2, _ := unlockKeys(lowerNoDashes(unlock), pub)
	if !bytes.Equal(ticket, ticket2) || !bytes.Equal(k, k2) {
		t.Fatal("the same unlock code gives different keys")
	}

	for _, secret := range []string{"12345", "", string(bytes.Repeat([]byte("x"), maxSecret))} {
		sealed, err := seal([]byte(secret), pub, k)
		if err != nil {
			t.Fatal(err)
		}
		if len(sealed) != sealedLen {
			t.Fatalf("sealed length %d, want %d", len(sealed), sealedLen)
		}
		got, err := open(sealed, priv, k)
		if err != nil || string(got) != secret {
			t.Fatalf("open: %q, %v", got, err)
		}
	}
	if _, err := seal(make([]byte, maxSecret+1), pub, k); err == nil {
		t.Fatal("a secret over 4 KB was sealed")
	}

	sealed, _ := seal([]byte("12345"), pub, k)
	// A wrong unlock code cannot open it.
	other, _ := newUnlockCode()
	_, kWrong, _ := unlockKeys(other, pub)
	if _, err := open(sealed, priv, kWrong); err == nil {
		t.Fatal("opened with the wrong unlock code")
	}
	// Another private key cannot open it.
	priv2, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := open(sealed, priv2, k); err == nil {
		t.Fatal("opened with another key")
	}
	// A changed byte is refused.
	sealed[len(sealed)-1] ^= 1
	if _, err := open(sealed, priv, k); err == nil {
		t.Fatal("opened a changed secret")
	}
}

func lowerNoDashes(s string) string {
	out := []byte{}
	for _, c := range []byte(s) {
		if c != '-' {
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			out = append(out, c)
		}
	}
	return string(out)
}

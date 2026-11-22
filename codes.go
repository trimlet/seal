package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
)

// The two codes Gino sends to Mario (docs/design.md section 3d): the code, which is Gino's
// X25519 public key, and the unlock code, 12 random characters. Both are written in Crockford
// base32 (digits and capital letters without I, L, O, U, so they can be dictated), in groups of 4.
// When read back, case, dashes and spaces are ignored, and I, L are read as 1, O as 0.

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

const (
	keyLen    = 32 // bytes of an X25519 key
	codeLen   = 52 // characters of the code: 256 bits, 5 per character
	unlockLen = 12 // characters of the unlock code: 60 bits
)

// encode32 writes b in Crockford base32, 5 bits per character, the last one padded with zeros.
func encode32(b []byte) string {
	var out strings.Builder
	var acc uint
	bits := 0
	for _, c := range b {
		acc = acc<<8 | uint(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out.WriteByte(crockford[(acc>>uint(bits))&31])
		}
	}
	if bits > 0 {
		out.WriteByte(crockford[(acc<<uint(5-bits))&31])
	}
	return out.String()
}

var errBadChar = errors.New("a character that is not in the code")

// normalize turns what was typed or pasted into the plain characters of a code.
func normalize(s string) (string, error) {
	var out strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch {
		case r == '-' || r == ' ' || r == '\t' || r == '\n' || r == '\r':
			continue
		case r == 'I' || r == 'L':
			r = '1'
		case r == 'O':
			r = '0'
		}
		if !strings.ContainsRune(crockford, r) {
			return "", errBadChar
		}
		out.WriteRune(r)
	}
	return out.String(), nil
}

// decode32 reads n bytes back from their Crockford base32 characters.
func decode32(s string, n int) ([]byte, error) {
	s, err := normalize(s)
	if err != nil {
		return nil, err
	}
	if len(s) != (n*8+4)/5 {
		return nil, errors.New("wrong length")
	}
	out := make([]byte, 0, n)
	var acc uint
	bits := 0
	for _, r := range s {
		acc = acc<<5 | uint(strings.IndexRune(crockford, r))
		bits += 5
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>uint(bits)))
		}
	}
	if acc&(1<<uint(bits)-1) != 0 {
		return nil, errors.New("not a code") // the padding bits must be zero
	}
	return out[:n], nil
}

// group puts a dash every 4 characters: QXJM-8VR2-…
func group(s string) string {
	var out strings.Builder
	for i, r := range s {
		if i > 0 && i%4 == 0 {
			out.WriteByte('-')
		}
		out.WriteRune(r)
	}
	return out.String()
}

// newKeys makes Gino's key pair: the code to send (the public key) and the private key,
// kept in pending.json in base64.
func newKeys() (code, key string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return group(encode32(priv.PublicKey().Bytes())), base64.StdEncoding.EncodeToString(priv.Bytes()), nil
}

// newUnlockCode makes 12 random characters, grouped: K7QM-4XRT-9BZ2.
// Each byte gives one character: 32 divides 256, so every character is equally likely.
func newUnlockCode() (string, error) {
	b := make([]byte, unlockLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, unlockLen)
	for i, c := range b {
		out[i] = crockford[c&31]
	}
	return group(string(out)), nil
}

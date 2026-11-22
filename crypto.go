package main

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// The crypto of Trimlet Seal, as written in docs/apps/seal.md ("The crypto"): standard pieces only,
// X25519, Argon2id, HKDF-SHA256, XChaCha20-Poly1305. "v1" names this version: the costs and labels
// below must never change for v1, or secrets sent with them could not be opened.

const version = "trimletseal-v1"

// Argon2id costs, fixed for v1.
const (
	argonTime    = 20
	argonMemory  = 256 * 1024 // KiB: 256 MiB
	argonThreads = 4
)

// maxSecret is the biggest secret, in bytes (decided: 4 KB, text only).
const maxSecret = 4096

// sealedLen is the size of every encrypted secret: version byte, E, nonce, padded secret, tag.
const sealedLen = 1 + keyLen + chacha20poly1305.NonceSizeX + 2 + maxSecret + chacha20poly1305.Overhead

// unlockKeys turns the unlock code into the ticket (shown to the server) and k (never sent),
// for the code whose public key is pub. It takes about a second on purpose (Argon2id).
func unlockKeys(unlock string, pub []byte) (ticket, k []byte, err error) {
	u, err := normalize(unlock)
	if err != nil {
		return nil, nil, err
	}
	if len(u) != unlockLen {
		return nil, nil, errors.New("an unlock code has 12 characters")
	}
	s := argon2.IDKey([]byte(u), append([]byte(version), pub...), argonTime, argonMemory, argonThreads, 32)
	if ticket, err = hkdf.Expand(sha256.New, s, version+" ticket", 32); err != nil {
		return nil, nil, err
	}
	if k, err = hkdf.Expand(sha256.New, s, version+" unlock", 32); err != nil {
		return nil, nil, err
	}
	return ticket, k, nil
}

// ticketHash is what Gino's app gives the server when it registers the code.
func ticketHash(ticket []byte) []byte {
	h := sha256.Sum256(ticket)
	return h[:]
}

// secretKey is the key of one secret: X25519 between E and the code, mixed with k.
func secretKey(dh, k, ePub, pub []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, append(append([]byte(nil), dh...), k...), append(append([]byte(nil), ePub...), pub...), version+" secret", chacha20poly1305.KeySize)
}

func associated(ePub, pub []byte) []byte {
	return append(append([]byte(version), ePub...), pub...)
}

// seal encrypts secret for the code pub, with k from the unlock code. Mario's side.
func seal(secret []byte, pub, k []byte) ([]byte, error) {
	if len(secret) > maxSecret {
		return nil, errors.New("the secret is longer than 4 KB")
	}
	codeKey, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	e, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	dh, err := e.ECDH(codeKey)
	if err != nil {
		return nil, err
	}
	ePub := e.PublicKey().Bytes()
	key, err := secretKey(dh, k, ePub, pub)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	// Padded to 4 KB, so the server does not learn how long the secret is.
	padded := make([]byte, 2+maxSecret)
	binary.BigEndian.PutUint16(padded, uint16(len(secret)))
	copy(padded[2:], secret)

	out := make([]byte, 0, sealedLen)
	out = append(out, 1)
	out = append(out, ePub...)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out = append(out, nonce...)
	return aead.Seal(out, nonce, padded, associated(ePub, pub)), nil
}

var errCannotOpen = errors.New("cannot be opened")

// open decrypts what seal made, with Gino's private key and k. Gino's side (block 3).
func open(sealed []byte, priv *ecdh.PrivateKey, k []byte) ([]byte, error) {
	if len(sealed) != sealedLen || sealed[0] != 1 {
		return nil, errCannotOpen
	}
	ePub := sealed[1 : 1+keyLen]
	nonce := sealed[1+keyLen : 1+keyLen+chacha20poly1305.NonceSizeX]
	e, err := ecdh.X25519().NewPublicKey(ePub)
	if err != nil {
		return nil, errCannotOpen
	}
	dh, err := priv.ECDH(e)
	if err != nil {
		return nil, errCannotOpen
	}
	pub := priv.PublicKey().Bytes()
	key, err := secretKey(dh, k, ePub, pub)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	padded, err := aead.Open(nil, nonce, sealed[1+keyLen+len(nonce):], associated(ePub, pub))
	if err != nil {
		return nil, errCannotOpen
	}
	n := int(binary.BigEndian.Uint16(padded))
	if n > maxSecret {
		return nil, errCannotOpen
	}
	return padded[2 : 2+n], nil
}

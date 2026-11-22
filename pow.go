package main

import (
	"encoding/binary"
	"math"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

// The proof of work (blocks 5 and 5b, docs/apps/seal.md), the same as trimletseal-server's
// src/pow.rs: Argon2id(challenge ‖ subject ‖ nonce, salt "trimletseal-v1 pow", t=1, m=4 MiB, p=1), 32
// bytes; the first 8, read as a number, must be at most MaxUint64 / difficulty. A solution takes
// `difficulty` tries on average (1.6 ms each on the author's Mac). The server chooses the difficulty.
// The subject is the code for a new code, "key" for a new access key, the key (base64) for a place.

const powSalt = "trimletseal-v1 pow"

func powWork(challenge []byte, subject string, nonce uint64) []byte {
	input := make([]byte, 0, len(challenge)+len(subject)+8)
	input = append(input, challenge...)
	input = append(input, subject...)
	input = binary.BigEndian.AppendUint64(input, nonce)
	return argon2.IDKey(input, []byte(powSalt), 1, 4*1024, 1, 32)
}

func powMeets(hash []byte, difficulty uint64) bool {
	return binary.BigEndian.Uint64(hash[:8]) <= math.MaxUint64/max(difficulty, 1)
}

// powSolve searches a nonce for the subject.
func powSolve(challenge []byte, subject string, difficulty uint64) uint64 {
	n, _ := powSearch(challenge, subject, difficulty, nil, nil, nil)
	return n
}

// powSearch is powSolve for the long work: it counts the tries in tries, calls tick about every
// second (to redraw the time left), and gives up when stop is set (false then).
func powSearch(challenge []byte, subject string, difficulty uint64, tries *atomic.Uint64, tick func(), stop *atomic.Bool) (uint64, bool) {
	last := time.Now()
	for n := uint64(0); ; n++ {
		if stop != nil && stop.Load() {
			return 0, false
		}
		if powMeets(powWork(challenge, subject, n), difficulty) {
			return n, true
		}
		if tries != nil {
			tries.Add(1)
		}
		if tick != nil && n%64 == 0 && time.Since(last) >= time.Second {
			last = time.Now()
			tick()
		}
	}
}

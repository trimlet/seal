# Trimlet Seal

Pass one confidential piece of information (a password, an alarm code, credentials) from one person to
another, once, in a small window driven only by the keyboard.

- The receiver asks for it: the app makes **a code** and **an unlock code**, which the receiver sends to
  the sender on two different channels (for example email and a messaging app).
- The sender pastes both, types the secret, picks how long it can wait (1, 2 or 24 hours) and sends.
  The secret is encrypted on the sender's computer for the receiver's app only.
- The receiver reads it once; then it is gone from the server, and the secret is never written to the
  disk of either computer.
  If someone else took it first, the receiver sees "delivered elsewhere".
- No accounts, no personal data. The server (vault.trimlet.dev) keeps only encrypted secrets and
  codes, for at most 24 hours and 7 days.

The crypto uses standard pieces (X25519, Argon2id, HKDF, XChaCha20-Poly1305) and has not been reviewed
by an expert yet.

## Download

The app for **macOS** (Mac with Apple chip: M1 and later) and **Windows** is on the
[Releases](https://github.com/trimlet/seal/releases) page. It is a beta (0.x), and not signed yet: the first
time, macOS asks to confirm (right click on the app → Open), Windows shows SmartScreen (More info →
Run anyway).

## Build

Written in Go with [Fyne](https://fyne.io). To build it, with Go installed (and on a Mac the Xcode
command line tools):

```
go run fyne.io/tools/cmd/fyne@v1.7.3 package --release
```

or `go run .` to try it. The console window comes from [trimlet/gui](https://github.com/trimlet/gui),
which `go` fetches by itself.

## How it is made

The code is written with Claude Opus (Anthropic), under the direction and review of a developer with
almost 30 years of experience. Every feature starts from a real, repeated need, and most ideas are
turned down: the goal is to stay small.

## License

GPL-3.0, see [LICENSE](LICENSE).

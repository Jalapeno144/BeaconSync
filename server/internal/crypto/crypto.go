// highest abstract layer of crypto module
// SecureSession orchestrates ECDH key exchange → HKDF key derivation →
// AEAD encryption/decryption through a single unified API.

//   ┌── cmd/client/main.go ───────────────────────────────────┐
//   │  config.Load() → cli.New() → app.Run()                  │
//   │                         ↓                               │
//   │              ┌── internal/cli ───┐                      │
//   │              │  connect()  ←──→  crypto.Handshake       │
//   │              │  send()     ←──→  crypto.Encrypt/Decrypt │
//   │              └───────────────────┘                      │
//   │                         ↓                               │
//   │              ┌── internal/transport ──┐                 │
//   │              │  HTTP GET/POST  (raw bytes)              │
//   │              └────────────────────────┘                 │
//   └─────────────────────────────────────────────────────────┘

// ┌── cmd/server/main.go ──────────────────────────────────┐
// │  /handshake  ←──  crypto.NewServerSession + Handshake  │
// │  /data       ←──  crypto.Decrypt + Encrypt             │
// └────────────────────────────────────────────────────────┘
package crypto

import (
	"crypto/ecdh"
	"fmt"
)

// SecureSession manages the full lifecycle of an encrypted session:
// key generation → handshake → encryption/decryption.
//
// Usage (client):
//
//	sess, _ := GenerateSession()
//	  send sess.PublicKeyBytes() to server
//	sess.Handshake(serverPubBytes, salt, info)
//	cipher, _ := sess.Encrypt([]byte("hello"))
//
// Usage (server):
//
//	sess := NewServerSession(serverPriv)
//	  receive clientPubBytes, send sess.PublicKeyBytes()
//	sess.Handshake(clientPubBytes, salt, info)
//	plain, _ := sess.Decrypt(cipher)
type SecureSession struct {
	privateKey *ecdh.PrivateKey
	publicKey  *ecdh.PublicKey
	sessionKey []byte
}

// NewServerSession creates a session using an existing X25519 private key.
// Typically used on the server side, where the key may be persisted across
// multiple client sessions.
func NewServerSession(privKey *ecdh.PrivateKey) *SecureSession {
	return &SecureSession{
		privateKey: privKey,
		publicKey:  privKey.PublicKey(),
	}
}

// GenerateSession creates a session with a fresh ephemeral X25519 key pair.
// Typically used on the client side, or whenever per-session key rotation
// is desired.
func GenerateSession() (*SecureSession, error) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("crypto: generate session: %w", err)
	}
	return &SecureSession{
		privateKey: priv,
		publicKey:  pub,
	}, nil
}

// PublicKeyBytes returns the raw 32-byte X25519 public key, ready to be
// transmitted to the peer for ECDH key agreement.
func (s *SecureSession) PublicKeyBytes() []byte {
	return s.publicKey.Bytes()
}

// Handshake completes the ECDH key agreement with the peer's raw public key
// and derives the 32-byte AES-256 session key via HKDF-SHA256.
//
//	salt — optional (nil uses an all-zero salt per RFC 5869)
//	info — protocol-specific context (binds the derived key to this session)
//
// After a successful handshake, Encrypt and Decrypt are ready to use.
func (s *SecureSession) Handshake(peerPubBytes, salt, info []byte) error {
	peerPub, err := ParsePublicKey(peerPubBytes)
	if err != nil {
		return fmt.Errorf("crypto: handshake: %w", err)
	}

	sharedSecret, err := ComputeSharedSecret(s.privateKey, peerPub)
	if err != nil {
		return fmt.Errorf("crypto: handshake: %w", err)
	}

	s.sessionKey, err = DeriveKey(sharedSecret, salt, info)
	if err != nil {
		return fmt.Errorf("crypto: handshake: %w", err)
	}

	return nil
}

// Encrypt encrypts plaintext with AES-256-GCM using the derived session key.
// Each call generates a fresh random 12-byte nonce — safe to reuse the key.
//
// Output format: [nonce:12][ciphertext + 16-byte authentication tag].
// Handshake must be called first.
func (s *SecureSession) Encrypt(plaintext []byte) ([]byte, error) {
	if s.sessionKey == nil {
		return nil, fmt.Errorf("crypto: encrypt: session key not established — call Handshake first")
	}
	return Encrypt(s.sessionKey, plaintext)
}

// Decrypt reverses Encrypt. Handshake must be called first.
func (s *SecureSession) Decrypt(ciphertext []byte) ([]byte, error) {
	if s.sessionKey == nil {
		return nil, fmt.Errorf("crypto: decrypt: session key not established — call Handshake first")
	}
	return Decrypt(s.sessionKey, ciphertext)
}

// IsEstablished reports whether the handshake has completed and the
// session key is ready for use.
func (s *SecureSession) IsEstablished() bool {
	return s.sessionKey != nil
}

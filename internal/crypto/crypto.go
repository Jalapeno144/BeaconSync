package crypto

import (
	"crypto/ecdh"
	"fmt"
)

// — Wire protocol constants —
const (
	msgHandshake     = 0x01 // client → server: [0x01][pubkey:32][optional plaintext]
	msgHandshakeResp = 0x02 // server → client: [0x02][pubkey:32][optional AEAD payload]
	msgData          = 0x03 // either direction: [0x03][AEAD payload]
)

const pubKeySize = 32 // X25519

// SecureSession manages an end-to-end encrypted channel on top of an
// already-established TLS connection (the "outer" TLS).
//
// The outer TLS passes through enterprise proxies without raising alerts;
// this layer provides the actual confidentiality.
//
// Lifecycle:
//
//  1. NewSecureSession() — generate ephemeral X25519 keypair
//  2. WrapOutgoing()     — before handshake: attach public key; after: AEAD encrypt
//  3. UnwrapIncoming()   — detect handshake response, derive session key, decrypt
//
// Both WrapOutgoing and UnwrapIncoming are safe to call before the handshake
// is complete — they will produce/consume messages that include the key
// material needed to finish the exchange.
type SecureSession struct {
	ourPrivBytes []byte           // raw private key (cleared after handshake)
	ourPubBytes  []byte           // raw public key
	sessKey      []byte           // AES-256 key derived via HKDF-SHA256
	ready        bool             // handshake complete?
}

// NewSecureSession creates a fresh SecureSession with a new ephemeral keypair.
func NewSecureSession() (*SecureSession, error) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("secure session: %w", err)
	}
	return &SecureSession{
		ourPrivBytes: priv.Bytes(),
		ourPubBytes:  pub.Bytes(),
	}, nil
}

// IsReady reports whether the handshake has completed and AEAD encryption is
// available for WrapOutgoing / UnwrapIncoming.
func (s *SecureSession) IsReady() bool {
	return s.ready
}

// PublicKeyBytes returns our ephemeral public key (32 bytes, X25519).
func (s *SecureSession) PublicKeyBytes() []byte {
	return s.ourPubBytes
}

// — Wire protocol —

// WrapOutgoing prepares plaintext for transmission to the server.
//
// Before handshake:  [msgHandshake][ourPub:32][plaintext]   (plaintext in clear)
// After handshake:   [msgData][AEAD(plaintext)]
func (s *SecureSession) WrapOutgoing(plaintext []byte) ([]byte, error) {
	if s.ready {
		ct, err := Encrypt(s.sessKey, plaintext)
		if err != nil {
			return nil, fmt.Errorf("wrap: %w", err)
		}
		out := make([]byte, 0, 1+len(ct))
		out = append(out, msgData)
		out = append(out, ct...)
		return out, nil
	}

	// Before handshake — include our public key.
	out := make([]byte, 0, 1+pubKeySize+len(plaintext))
	out = append(out, msgHandshake)
	out = append(out, s.ourPubBytes...)
	out = append(out, plaintext...)
	return out, nil
}

// UnwrapIncoming processes data received from the server.
//
//   - msgHandshakeResp → completes key exchange, returns any AEAD-decrypted payload.
//   - msgData          → AEAD-decrypts and returns the payload.
//   - anything else    → passed through as-is (legacy / plaintext fallback).
//
// Returns (nil, nil) when the message carries no application data.
func (s *SecureSession) UnwrapIncoming(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	switch data[0] {
	case msgHandshakeResp:
		return s.handleHandshakeResp(data[1:])
	case msgData:
		if !s.ready {
			return nil, fmt.Errorf("unwrap: received data before handshake complete")
		}
		return Decrypt(s.sessKey, data[1:])
	default:
		// Legacy plaintext — pass through.
		return data, nil
	}
}

// — Handshake —

func (s *SecureSession) handleHandshakeResp(payload []byte) ([]byte, error) {
	if len(payload) < pubKeySize {
		return nil, fmt.Errorf("handshake response: need %d bytes, got %d", pubKeySize, len(payload))
	}

	peerPubRaw := payload[:pubKeySize]
	rest := payload[pubKeySize:]

	// Rebuild our *ecdh.PrivateKey from raw bytes.
	ourPriv, err := ecdh.X25519().NewPrivateKey(s.ourPrivBytes)
	if err != nil {
		return nil, fmt.Errorf("handshake: rebuild private key: %w", err)
	}

	peerPub, err := ecdh.X25519().NewPublicKey(peerPubRaw)
	if err != nil {
		return nil, fmt.Errorf("handshake: parse server public key: %w", err)
	}

	shared, err := ourPriv.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("handshake: ecdh: %w", err)
	}

	sessKey, err := DeriveKey(shared, nil, []byte("beaconsync-session-v1"))
	if err != nil {
		return nil, fmt.Errorf("handshake: hkdf: %w", err)
	}

	s.sessKey = sessKey
	s.ready = true

	// Clear private key for forward secrecy.
	s.ourPrivBytes = nil

	if len(rest) == 0 {
		return nil, nil
	}
	return Decrypt(s.sessKey, rest)
}

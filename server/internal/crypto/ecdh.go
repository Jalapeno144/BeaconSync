package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
)

// GenerateKeyPair creates a fresh X25519 ephemeral key pair for ECDH.
func GenerateKeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ecdh generate: %w", err)
	}
	return priv, priv.PublicKey(), nil
}

// ParsePublicKey decodes a raw 32-byte X25519 public key.
func ParsePublicKey(pubBytes []byte) (*ecdh.PublicKey, error) {
	return ecdh.X25519().NewPublicKey(pubBytes)
}

// ComputeSharedSecret performs ECDH key agreement between our private key
// and the peer's public key, returning the raw shared secret.
func ComputeSharedSecret(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	return priv.ECDH(pub)
}

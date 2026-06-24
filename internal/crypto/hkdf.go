package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
)

// DeriveKey derives a 32-byte AES-256 key from the shared secret using
// HKDF-SHA256 (RFC 5869). Uses only the standard library — zero external
// dependencies.
//
//	salt  — optional (nil → all-zero hash-sized salt)
//	info  — context string that binds the key to this protocol
func DeriveKey(secret, salt, info []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("hkdf: secret must not be empty")
	}

	// — Extract —
	// PRK = HMAC-SHA256(salt, IKM)
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	prk := hmacSHA256(salt, secret)

	// — Expand —
	// T(1) = HMAC-SHA256(PRK, info || 0x01)
	// For AES-256 we only need 32 bytes = one HMAC-SHA256 output.
	var prev []byte
	key := make([]byte, 0, 32)

	for i := byte(1); len(key) < 32; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{i})
		prev = h.Sum(nil)
		key = append(key, prev...)
	}

	return key[:32], nil
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// Ensure hash.Hash satisfaction at compile time (unused var, just for type check).
var _ hash.Hash = sha256.New()

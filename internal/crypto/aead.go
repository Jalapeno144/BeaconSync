package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const nonceSize = 12 // AES-GCM standard nonce

// Encrypt encrypts plaintext with AES-256-GCM using a random 12-byte nonce.
//
// Output format: [nonce:12][ciphertext + 16-byte tag]
// Each call generates a fresh random nonce — safe to reuse the same key.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aead encrypt: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aead encrypt: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("aead encrypt nonce: %w", err)
	}

	// Seal appends ciphertext to nonce, returning [nonce || ciphertext+tag]
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt. Expects input in the format produced by Encrypt.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("aead decrypt: ciphertext too short (%d bytes)", len(ciphertext))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aead decrypt: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aead decrypt: %w", err)
	}

	nonce := ciphertext[:nonceSize]
	return gcm.Open(nil, nonce, ciphertext[nonceSize:], nil)
}

func EncryptData(key []byte, plaintext string) (string, error) {
	//TODO
	return "a", nil
}

func DecryptData(key []byte, value string) (string, error) {
	//TODO
	return "a", nil
}

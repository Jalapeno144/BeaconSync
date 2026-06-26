// highest abstract layer of crypto module
package crypto

import (
	"crypto/ecdh"
)

type SecureSession struct {
	serverPrivateKey *ecdh.PrivateKey
	sessionKey       []byte
}

func NewServerSession(privKey *ecdh.PrivateKey) *SecureSession {
	return &SecureSession{serverPrivateKey: privKey}
}

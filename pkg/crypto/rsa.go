package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// EncryptRSA encrypts data using a PEM-encoded RSA Public Key.
// Uses OAEP with SHA-256. Returns Base64 encoded ciphertext.
func EncryptRSA(data string, pubKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		return "", errors.New("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("key is not of type RSA pointer")
	}

	// OAEP with SHA-256
	ciphertext, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		rsaPub,
		[]byte(data),
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

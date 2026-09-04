package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

func testPublicKeyPEM(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return string(pemBytes), key
}

func TestEncryptRSARoundTrip(t *testing.T) {
	pubPEM, priv := testPublicKeyPEM(t)

	const secret = "iban: FR76 3000 6000 0112 3456 7890 189"
	ct, err := EncryptRSA(secret, pubPEM)
	if err != nil {
		t.Fatalf("EncryptRSA: %v", err)
	}
	if ct == secret || ct == "" {
		t.Fatal("ciphertext looks wrong")
	}

	raw, err := base64.StdEncoding.DecodeString(ct)
	if err != nil {
		t.Fatalf("ciphertext not base64: %v", err)
	}
	plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, raw, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(plain) != secret {
		t.Fatalf("round trip mismatch: %q", plain)
	}
}

func TestEncryptRSARejectsBadPEM(t *testing.T) {
	if _, err := EncryptRSA("x", "not a pem block"); err == nil {
		t.Fatal("expected an error for invalid PEM")
	}
}

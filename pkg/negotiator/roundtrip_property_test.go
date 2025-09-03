package negotiator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"testing/quick"
)

// Property-based test: plaintext random selalu roundtrip benar
func TestNegotiator_Roundtrip_Property(t *testing.T) {
	f := func(msg []byte) bool {
		// Generate fresh RSA keypair
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		pub := &priv.PublicKey

		// Convert keys ke PEM
		privPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		})
		pubBytes, _ := x509.MarshalPKIXPublicKey(pub)
		pubPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		})

		// Init target + receiver
		target, _ := NewNegotiateTarget(pubPEM)
		receiver, _ := NewNegotiateReceiver(privPEM)

		// Encrypt
		meta := &UserMeta{Name: "rand.bin", MimeType: "application/octet-stream"}
		encrypted, err := target.Encrypt256(msg, meta)
		if err != nil {
			return false
		}

		// Decrypt
		decrypted, err := receiver.DecryptHybrid(encrypted)
		if err != nil {
			return false
		}

		// Assert roundtrip
		return string(msg) == string(decrypted.Plain)
	}

	if err := quick.Check(f, nil); err != nil {
		t.Errorf("property-based roundtrip failed: %v", err)
	}
}

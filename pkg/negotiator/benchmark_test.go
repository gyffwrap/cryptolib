package negotiator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func BenchmarkNegotiator_EncryptDecrypt(b *testing.B) {
	// Generate static RSA keypair (biar ga regenerasi tiap iterasi)
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	pubBytes, _ := x509.MarshalPKIXPublicKey(pub)
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	target, _ := NewNegotiateTarget(pubPEM)
	receiver, _ := NewNegotiateReceiver(privPEM)

	plaintext := []byte("benchmark test message, cukup panjang biar meaningful")
	userMeta := &UserMeta{Name: "bench.txt", MimeType: "text/plain"}

	b.ResetTimer() // reset timer sebelum loop
	for i := 0; i < b.N; i++ {
		// Encrypt
		encrypted, err := target.Encrypt256(plaintext, userMeta)
		if err != nil {
			b.Fatalf("Encrypt failed: %v", err)
		}

		// Decrypt
		_, err = receiver.DecryptHybrid(encrypted)
		if err != nil {
			b.Fatalf("Decrypt failed: %v", err)
		}
	}
}

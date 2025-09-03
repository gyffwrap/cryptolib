package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func TestEncryption(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	publicKey := &privateKey.PublicKey

	plaintext := []byte("this is a secret message")
	h := sha256.New()

	t.Run("Encrypt", func(t *testing.T) {
		ciphertext, err := Encrypt(plaintext, h, publicKey)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}
		if len(ciphertext) == 0 {
			t.Error("Encrypt returned empty ciphertext")
		}
	})

	t.Run("EncryptToBase64", func(t *testing.T) {
		ciphertextB64, err := EncryptToBase64(plaintext, h, publicKey)
		if err != nil {
			t.Fatalf("Encryption to Base64 failed: %v", err)
		}
		if len(ciphertextB64) == 0 {
			t.Error("EncryptToBase64 returned empty string")
		}
	})

	t.Run("Encrypt with Nil Key", func(t *testing.T) {
		_, err := Encrypt(plaintext, h, nil)
		if err == nil {
			t.Error("Expected an error for nil public key, but got nil")
		}
	})
}

package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func TestDecryption(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}
	publicKey := &privateKey.PublicKey

	plaintext := []byte("this is a secret message")
	h := sha256.New()

	// We need to encrypt first to get something to decrypt
	ciphertext, err := Encrypt(plaintext, h, publicKey)
	if err != nil {
		t.Fatalf("Prerequisite encryption failed: %v", err)
	}

	ciphertextB64, err := EncryptToBase64(plaintext, h, publicKey)
	if err != nil {
		t.Fatalf("Prerequisite encryption to Base64 failed: %v", err)
	}

	t.Run("Decrypt", func(t *testing.T) {
		decrypted, err := Decrypt(ciphertext, h, privateKey)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}
		if string(plaintext) != string(decrypted) {
			t.Errorf("Decrypted text does not match original. Got '%s', want '%s'", string(decrypted), string(plaintext))
		}
	})

	t.Run("DecryptFromBase64", func(t *testing.T) {
		decrypted, err := DecryptFromBase64(ciphertextB64, h, privateKey)
		if err != nil {
			t.Fatalf("Decryption from Base64 failed: %v", err)
		}
		if string(plaintext) != string(decrypted) {
			t.Errorf("Decrypted text from Base64 does not match original. Got '%s', want '%s'", string(decrypted), string(plaintext))
		}
	})

	t.Run("Decrypt with Nil Key", func(t *testing.T) {
		_, err := Decrypt(ciphertext, h, nil)
		if err == nil {
			t.Error("Expected an error for nil private key, but got nil")
		}
	})
}

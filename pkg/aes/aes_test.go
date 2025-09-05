package aes

import (
	"encoding/base64"
	"testing"
)

func TestEncryptDecryptAES(t *testing.T) {
	plaintext := []byte("this is a very secret message")

	t.Run("Encrypt with generated key and Decrypt", func(t *testing.T) {
		// Encrypt with a generated 32-byte (AES-256) key
		encryptResult, err := Encrypt(plaintext, nil) // Use nil args to generate a key
		if err != nil {
			t.Fatalf("Encryption with generated key failed: %v", err)
		}

		// Decrypt
		decrypted, err := Decrypt(encryptResult.Ciphertext, encryptResult.Key, encryptResult.Nonce)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		// Verify
		if string(plaintext) != string(decrypted) {
			t.Errorf("Decrypted text does not match original. Got '%s', want '%s'", string(decrypted), string(plaintext))
		}
	})

	t.Run("Encrypt with provided key and Decrypt", func(t *testing.T) {
		// Encrypt with a user-provided 16-byte (AES-128) key
		userKey := []byte("a 16-byte key..") // 16 byte
		args := &Args{Key: &userKey}         // <- sesuaikan type

		encryptResult, err := Encrypt(plaintext, args)
		if err != nil {
			t.Fatalf("Encryption with provided key failed: %v", err)
		}

		// Decrypt
		decrypted, err := Decrypt(encryptResult.Ciphertext, encryptResult.Key, encryptResult.Nonce)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		// Verify
		if string(plaintext) != string(decrypted) {
			t.Errorf("Decrypted text does not match original. Got '%s', want '%s'", string(decrypted), string(plaintext))
		}
	})

	t.Run("DecryptFromBase64", func(t *testing.T) {
		// Encrypt to get data for the Base64 test
		encryptResult, err := Encrypt(plaintext, nil)
		if err != nil {
			t.Fatalf("Prerequisite encryption for Base64 test failed: %v", err)
		}

		// Encode data to Base64
		ciphertextB64 := base64.StdEncoding.EncodeToString(encryptResult.Ciphertext)
		keyB64 := base64.StdEncoding.EncodeToString(encryptResult.Key)
		nonceB64 := base64.StdEncoding.EncodeToString(encryptResult.Nonce)

		// Decrypt from Base64
		decrypted, err := DecryptFromBase64(ciphertextB64, keyB64, nonceB64)
		if err != nil {
			t.Fatalf("Decryption from Base64 failed: %v", err)
		}

		// Verify
		if string(plaintext) != string(decrypted) {
			t.Errorf("Decrypted text from Base64 does not match original. Got '%s', want '%s'", string(decrypted), string(plaintext))
		}
	})

	t.Run("Error on Invalid Key Size", func(t *testing.T) {
		invalidKey := []byte("short")
		args := &Args{Key: &invalidKey}
		_, err := Encrypt(plaintext, args)
		if err == nil {
			t.Error("Expected an error for invalid key size, but got nil")
		}
	})
}

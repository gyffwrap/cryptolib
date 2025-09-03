package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"

	cryptErr "github.com/gyffwrap/cryptolib/pkg/aes/errors"
)

func Decrypt(ciphertext []byte, key []byte, nonce []byte) ([]byte, error) {
	// Validasi key
	if len(key) != 16 && len(key) != 32 {
		return nil, cryptErr.ErrInvalidKeySize
	}

	// Buat AES block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", cryptErr.ErrCipherInit, err)
	}

	// GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", cryptErr.ErrGCMInit, err)
	}

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", cryptErr.ErrDecryptionFailed, err)
	}

	return plaintext, nil
}

func DecryptFromBase64(ciphertextB64 string, keyB64 string, nonceB64 string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", cryptErr.ErrBase64DecodeFailed, err)
	}

	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", cryptErr.ErrBase64DecodeFailed, err)
	}

	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", cryptErr.ErrBase64DecodeFailed, err)
	}

	return Decrypt(ciphertext, key, nonce)
}

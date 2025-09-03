package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"hash"

	cryptErr "github.com/gyffwrap/cryptolib/pkg/rsa/errors"
)

func Encrypt(plaintext []byte, h hash.Hash, pubKey *rsa.PublicKey) ([]byte, error) {
	if pubKey == nil {
		return nil, cryptErr.ErrNilPublicKey
	}

	// Gunakan OAEP dengan SHA-256
	ciphertext, err := rsa.EncryptOAEP(
		h,
		rand.Reader,
		pubKey,
		plaintext,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", cryptErr.ErrEncryptionFailed, err)
	}

	return ciphertext, nil
}

func EncryptToBase64(plaintext []byte, h hash.Hash, pubKey *rsa.PublicKey) (string, error) {
	ciphertext, err := Encrypt(plaintext, h, pubKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"hash"

	cryptErr "github.com/gyffwrap/cryptolib/pkg/rsa/errors"
)

func Decrypt(ciphertext []byte, h hash.Hash, privKey *rsa.PrivateKey) ([]byte, error) {
	if privKey == nil {
		return nil, cryptErr.ErrNilPrivateKey
	}

	plaintext, err := rsa.DecryptOAEP(
		h,
		rand.Reader,
		privKey,
		ciphertext,
		nil, // label optional, biasanya nil
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", cryptErr.ErrDecryptionFailed, err)
	}

	return plaintext, nil
}

func DecryptFromBase64(ciphertextB64 string, h hash.Hash, privKey *rsa.PrivateKey) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %v", err)
	}
	return Decrypt(ciphertext, h, privKey)
}

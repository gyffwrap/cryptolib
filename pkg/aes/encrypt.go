package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	cryptErr "github.com/gyffwrap/cryptolib/pkg/aes/errors"
)

type Args struct {
	Key      *[]byte
	ByteCode *int
}

func Encrypt(plaintext []byte, args *Args) (*AESResult, error) {
	var keyBytes []byte
	var byteCode int

	// 1. Tentukan keyBytes
	if args != nil && args.Key != nil {
		keyBytes = *args.Key
		byteCode = len(keyBytes)
	} else {
		if args != nil && args.ByteCode != nil {
			byteCode = *args.ByteCode
		} else {
			byteCode = 32 // default AES-256
		}

		keyBytes = make([]byte, byteCode)
		if _, err := io.ReadFull(rand.Reader, keyBytes); err != nil {
			return nil, fmt.Errorf("%w: %v", cryptErr.ErrKeyGeneration, err)
		}
	}

	// 2. Validasi key length
	if byteCode != 16 && byteCode != 32 {
		return nil, cryptErr.ErrInvalidKeySize
	}

	// 3. Buat AES cipher block
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", cryptErr.ErrCipherInit, err)
	}

	// 4. GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", cryptErr.ErrGCMInit, err)
	}

	// 5. Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("%w: %v", cryptErr.ErrNonceGeneration, err)
	}

	// 6. Encrypt
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return &AESResult{
		Ciphertext: ciphertext,
		Key:        keyBytes,
		Nonce:      nonce,
	}, nil
}

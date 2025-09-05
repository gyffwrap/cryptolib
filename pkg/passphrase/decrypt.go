package passphrase

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	aespkg "github.com/gyffwrap/cryptolib/pkg/aes"
	cryptErr "github.com/gyffwrap/cryptolib/pkg/aes/errors"
	"golang.org/x/crypto/argon2"
)

type UnwrapResult struct {
	Plain    []byte
	UserMeta UserMeta
}

func Decrypt(payload string, passphrase string) (*UnwrapResult, error) {
	if payload == "" || passphrase == "" {
		return nil, cryptErr.ErrInvalidKeySize
	}

	parts := strings.SplitN(payload, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("invalid payload format")
	}

	metaB64 := parts[0]
	cipherB64 := parts[1]

	metaJSON, err := base64.StdEncoding.DecodeString(metaB64)
	if err != nil {
		return nil, fmt.Errorf("decode meta: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(cipherB64)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	// 2. Unmarshal meta
	var meta Meta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return nil, fmt.Errorf("unmarshal meta: %w", err)
	}

	// 3. Check version
	if meta.Version != Version {
		return nil, fmt.Errorf("unsupported meta version: %d", meta.Version)
	}

	// 4. Derive key - passphrase + salt
	keyLen := len(ciphertext)
	if keyLen != 16 && keyLen != 32 {
		// fallback default ke 32
		keyLen = 32
	}
	key := argon2.IDKey([]byte(passphrase), meta.Salt, 1, 64*1024, 4, uint32(keyLen))

	// 5. AES decrypt
	plaintext, err := aespkg.Decrypt(ciphertext, key, meta.Nonce)
	if err != nil {
		return nil, fmt.Errorf("aes decrypt: %w", err)
	}

	return &UnwrapResult{
		Plain:    plaintext,
		UserMeta: meta.UserMeta,
	}, nil
}

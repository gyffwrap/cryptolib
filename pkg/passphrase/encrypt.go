package passphrase

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	aespkg "github.com/gyffwrap/cryptolib/pkg/aes"
	cryptErr "github.com/gyffwrap/cryptolib/pkg/aes/errors"
	"golang.org/x/crypto/argon2"
)

const Version = 1

type UserMeta struct {
	Filename string `json:"filename,omitempty"`
	Mime     string `json:"mime,omitempty"`
}

type Args struct {
	Passphrase string
	ByteCode   int // 16 or 32
	UserMeta   UserMeta
}

type PPResult struct {
	Payload string // base64(metaJSON) + "." + base64(ciphertext)
}

type Meta struct {
	Salt     []byte   `json:"salt"`
	Nonce    []byte   `json:"nonce"`
	Version  int      `json:"version"`
	UserMeta UserMeta `json:"user_meta"`
}

func Encrypt(plaintext []byte, args *Args) (*PPResult, error) {
	if args == nil || args.Passphrase == "" {
		return nil, cryptErr.ErrInvalidKeySize
	}
	if args.ByteCode != 16 && args.ByteCode != 32 {
		return nil, cryptErr.ErrInvalidKeySize
	}

	// 1. Generate random salt
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	// 2. Derive key Argon2id
	key := argon2.IDKey([]byte(args.Passphrase), salt, 1, 64*1024, 4, uint32(args.ByteCode))

	// 3. Encrypt plaintext pakai AES GCM dari pkg/aes
	aesArgs := &aespkg.Args{
		Key:      &key,
		ByteCode: nil,
	}
	block, err := aespkg.Encrypt(plaintext, aesArgs)
	if err != nil {
		return nil, fmt.Errorf("aes encrypt: %w", err)
	}

	// 4. save meta
	meta := &Meta{
		Salt:     salt,
		Nonce:    block.Nonce,
		Version:  Version,
		UserMeta: args.UserMeta,
	}

	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("marshal meta: %w", err)
	}

	// 5. Gabungkan base64(metaJSON).base64(ciphertext)
	payload := fmt.Sprintf("%s.%s", base64.StdEncoding.EncodeToString(metaJSON), base64.StdEncoding.EncodeToString(block.Ciphertext))

	return &PPResult{
		Payload: payload,
	}, nil
}

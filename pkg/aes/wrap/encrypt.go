package wrap

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	aespkg "github.com/gyffwrap/cryptolib/pkg/aes"
	cryptErr "github.com/gyffwrap/cryptolib/pkg/aes/errors"
)

const Version = 1

type UserMeta struct {
	Filename string `json:"filename,omitempty"`
	Mime     string `json:"mime,omitempty"`
}

type Meta struct {
	MapKey   map[string][]byte `json:"mapkey"`  // langsung []byte
	Nonce    []byte            `json:"nonce"`   // nonce untuk payload
	Version  int               `json:"version"` // versi format
	UserMeta UserMeta          `json:"user_meta"`
}

type WrapArgs struct {
	ByteCode int
	UserMeta UserMeta
}

type WrapResult struct {
	Payload string // base64(metaJSON) + "." + base64(ciphertext)
}

func EncryptAndWrap(plaintext []byte, wrapKey []byte, args *WrapArgs) (*WrapResult, error) {
	if args == nil {
		return nil, fmt.Errorf("args is nil")
	}

	// 1) Validasi wrapKey
	if len(wrapKey) != 16 && len(wrapKey) != 32 {
		return nil, cryptErr.ErrInvalidKeySize
	}

	// 2) Validasi ByteCode
	dataSize := args.ByteCode
	if dataSize != 16 && dataSize != 32 {
		return nil, cryptErr.ErrInvalidKeySize
	}

	// 3) Encrypt payload dengan AES lokal (generate dataKey otomatis)
	dataAESRes, err := aespkg.Encrypt(plaintext, &aespkg.Args{ByteCode: &dataSize})
	if err != nil {
		return nil, fmt.Errorf("encrypt payload: %w", err)
	}
	dataKey := dataAESRes.Key
	ciphertext := dataAESRes.Ciphertext
	noncePayload := dataAESRes.Nonce

	// 4) Wrap (encrypt) dataKey dengan wrapKey
	wrapAESRes, err := aespkg.Encrypt(dataKey, &aespkg.Args{Key: &wrapKey})
	if err != nil {
		return nil, fmt.Errorf("wrap data key: %w", err)
	}
	encryptedDataKey := wrapAESRes.Ciphertext
	nonceWrap := wrapAESRes.Nonce

	// 5) Buat Meta
	meta := Meta{
		MapKey: map[string][]byte{
			"key":   encryptedDataKey,
			"nonce": nonceWrap,
		},
		Nonce:    noncePayload,
		Version:  Version,
		UserMeta: args.UserMeta,
	}

	// 6) Marshal dan encode base64
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("marshal meta: %w", err)
	}
	metaB64 := base64.StdEncoding.EncodeToString(metaJSON)
	payloadB64 := base64.StdEncoding.EncodeToString(ciphertext)

	fullPayload := metaB64 + "." + payloadB64

	return &WrapResult{
		Payload: fullPayload,
	}, nil
}

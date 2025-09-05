package wrap

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	aespkg "github.com/gyffwrap/cryptolib/pkg/aes"
	cryptErr "github.com/gyffwrap/cryptolib/pkg/aes/errors"
)

type UnwrapResult struct {
	Plain    []byte
	UserMeta UserMeta
}

func UnwrapAndDecrypt(fullPayload string, wrapKey []byte) (*UnwrapResult, error) {
	// 1) Validasi wrapKey
	if len(wrapKey) != 16 && len(wrapKey) != 32 {
		return nil, cryptErr.ErrInvalidKeySize
	}

	// 2) Split fullPayload
	parts := strings.SplitN(fullPayload, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid payload format")
	}
	metaB64 := parts[0]
	payloadB64 := parts[1]

	// 3) Decode base64
	metaJSON, err := base64.StdEncoding.DecodeString(metaB64)
	if err != nil {
		return nil, fmt.Errorf("decode meta base64: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("decode payload base64: %w", err)
	}

	// 4) Unmarshal meta
	var meta Meta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return nil, fmt.Errorf("unmarshal meta: %w", err)
	}

	// 5) Check version
	if meta.Version != 1 {
		return nil, fmt.Errorf("unsupported meta version: %d", meta.Version)
	}

	// 6) Ambil encryptedDataKey + nonceWrap
	encDataKey, ok := meta.MapKey["key"]
	if !ok || len(encDataKey) == 0 {
		return nil, fmt.Errorf("meta missing encrypted data key")
	}
	nonceWrap, ok := meta.MapKey["nonce"]
	if !ok || len(nonceWrap) == 0 {
		return nil, fmt.Errorf("meta missing wrap nonce")
	}

	// 7) Decrypt (unwrap) dataKey menggunakan wrapKey
	dataKey, err := aespkg.Decrypt(encDataKey, wrapKey, nonceWrap)
	if err != nil {
		return nil, fmt.Errorf("unwrap data key: %w", err)
	}

	// 8) Decrypt payload menggunakan dataKey + noncePayload
	plaintext, err := aespkg.Decrypt(ciphertext, dataKey, meta.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decrypt payload: %w", err)
	}

	return &UnwrapResult{
		Plain:    plaintext,
		UserMeta: meta.UserMeta,
	}, nil
}

package negotiator

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	cryErr "github.com/gyffwrap/cryptolib/pkg/negotiator/errors"

	"github.com/gyffwrap/cryptolib/pkg/aes"
	cryRsa "github.com/gyffwrap/cryptolib/pkg/rsa"
)

const Version = 1
const (
	AlgoRSAAES256GCM = "RSA-OAEP+AES-256-GCM"
)

type TargetNegotiate struct {
	publicKey *rsa.PublicKey
}

type UserMeta struct {
	Name     string `json:"name,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
}
type MetaData struct {
	Nonce   []byte `json:"nonce"`
	Key     []byte `json:"key"`
	Version int    `json:"version"`
	Algo    string `json:"algo"`
	UserMeta
}

func NewNegotiateTarget(publicKeyPEM []byte) (*TargetNegotiate, error) {
	if len(publicKeyPEM) == 0 {
		return nil, cryErr.ErrNilPublicKey
	}

	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, cryErr.ErrInvalidPEM
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		pubKey, err2 := x509.ParsePKCS1PublicKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("%w: PKIX err: %v, PKCS1 err: %v", cryErr.ErrParseFailed, err, err2)
		}
		return &TargetNegotiate{publicKey: pubKey}, nil
	}

	pubKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, cryErr.ErrNotRSAPublic
	}

	return &TargetNegotiate{publicKey: pubKey}, nil
}

func (p *TargetNegotiate) Encrypt256(plaintext []byte, userMeta *UserMeta) (string, error) {
	byteCode := 32

	// AES encrypt
	aesResult, err := aes.Encrypt(plaintext, &aes.Args{ByteCode: &byteCode})
	if err != nil {
		return "", fmt.Errorf("AES encrypt failed: %w", err)
	}

	nonce := aesResult.GetNonce()
	aesKey := aesResult.GetKey()

	// RSA encrypt AES key
	rsaEncryptedKey, err := cryRsa.Encrypt(aesKey, sha256.New(), p.publicKey)
	if err != nil {
		return "", fmt.Errorf("RSA encrypt failed: %w", err)
	}

	// Build metadata
	meta := MetaData{
		Nonce:    nonce,
		Key:      rsaEncryptedKey,
		Version:  Version,
		Algo:     AlgoRSAAES256GCM,
		UserMeta: *userMeta,
	}

	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return "", fmt.Errorf("marshal meta failed: %w", err)
	}

	// Encode meta + payload
	encodedMeta := base64.StdEncoding.EncodeToString(metaJSON)
	encodedPayload := aesResult.GetCiphertextBase64()

	combined := fmt.Sprintf("%s.%s", encodedMeta, encodedPayload)
	return combined, nil
}

package negotiator

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/gyffwrap/cryptolib/pkg/aes"
	cryErr "github.com/gyffwrap/cryptolib/pkg/negotiator/errors"
	cryRsa "github.com/gyffwrap/cryptolib/pkg/rsa"
)

type ReceiverNegotiate struct {
	privateKey *rsa.PrivateKey
}

type HybridDecrypted struct {
	Plain    []byte
	UserMeta UserMeta
}

// NewNegotiateReceiver membuat receiver dari private key PEM
func NewNegotiateReceiver(privateKeyPEM []byte) (*ReceiverNegotiate, error) {
	if len(privateKeyPEM) == 0 {
		return nil, cryErr.ErrNilPrivateKey
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, cryErr.ErrInvalidPEM
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		privInterface, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("%w: PKCS1 err: %v, PKCS8 err: %v",
				cryErr.ErrParseFailed, err, err2)
		}
		var ok bool
		privKey, ok = privInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, cryErr.ErrNotRSAPrivate
		}
	}

	return &ReceiverNegotiate{privateKey: privKey}, nil
}

// DecryptHybrid membaca output dari Encrypt256
func (r *ReceiverNegotiate) DecryptHybrid(encrypted string) (*HybridDecrypted, error) {
	if r == nil || r.privateKey == nil {
		return nil, cryErr.ErrNilPrivateKey
	}
	if encrypted == "" {
		return nil, cryErr.ErrInvalidPayload
	}

	// Pisahkan meta & payload
	parts := splitOnce(encrypted, ".")
	if len(parts) != 2 {
		return nil, cryErr.ErrInvalidPayload
	}
	metaB64, payloadB64 := parts[0], parts[1]

	// Decode & unmarshal meta
	metaJSON, err := base64.StdEncoding.DecodeString(metaB64)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", cryErr.ErrBase64DecodeFailed, err)
	}

	var meta MetaData
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return nil, fmt.Errorf("%w: %v", cryErr.ErrInvalidMetadata, err)
	}

	// Validasi version
	if meta.Version != Version {
		return nil, fmt.Errorf("%w: expected %d, got %d",
			cryErr.ErrVersionMismatch, Version, meta.Version)
	}

	// Validasi algo
	if meta.Algo != AlgoRSAAES256GCM {
		return nil, fmt.Errorf("%w: unsupported algo %s",
			cryErr.ErrUnsupportedAlgo, meta.Algo)
	}

	// Validasi nonce
	if len(meta.Nonce) == 0 {
		return nil, cryErr.ErrAESNonceGenFailed
	}

	// RSA decrypt AES key
	aesKey, err := cryRsa.Decrypt(meta.Key, sha256.New(), r.privateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", cryErr.ErrRSADecryptionFailed, err)
	}

	// Decode ciphertext
	ciphertext, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", cryErr.ErrBase64DecodeFailed, err)
	}

	// AES decrypt
	plain, err := aes.Decrypt(ciphertext, aesKey, meta.Nonce)
	if err != nil {
		// gabung error AES + sentinel
		return nil, errors.Join(cryErr.ErrAESDecryptionFailed, err)
	}

	// Return hanya plaintext + usermeta
	return &HybridDecrypted{
		Plain:    plain,
		UserMeta: meta.UserMeta,
	}, nil
}

// splitOnce membagi string hanya pada pemisah pertama
func splitOnce(s, sep string) []string {
	idx := strings.Index(s, sep)
	if idx < 0 {
		return []string{s}
	}
	return []string{s[:idx], s[idx+len(sep):]}
}

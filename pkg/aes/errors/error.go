package errors

import "errors"

var (
	// AES umum
	ErrInvalidKeySize     = errors.New("invalid key size (must be 16 or 32 bytes)")
	ErrCipherInit         = errors.New("failed to initialize AES cipher")
	ErrGCMInit            = errors.New("failed to initialize GCM")
	ErrKeyGeneration      = errors.New("failed to generate random key")
	ErrNonceGeneration    = errors.New("failed to generate random nonce")
	ErrEncryptionFailed   = errors.New("failed to encrypt data")
	ErrDecryptionFailed   = errors.New("failed to decrypt data")
	ErrBase64DecodeFailed = errors.New("failed to decode base64 input")
	ErrBase64EncodeFailed = errors.New("failed to encode base64 output")

	// AES Key Wrap (RFC 3394)
	ErrInvalidPlaintext  = errors.New("aes-wrap: plaintext must be at least 16 bytes and multiple of 8 bytes")
	ErrInvalidCiphertext = errors.New("aes-wrap: ciphertext must be at least 24 bytes and multiple of 8 bytes")
	ErrIntegrityCheck    = errors.New("aes-wrap: integrity check failed")

	// Wrapping layer (meta + payload)
	ErrInvalidPayloadFormat = errors.New("invalid payload format (expected meta.payload)")
	ErrMetaUnmarshalFailed  = errors.New("failed to unmarshal meta")
	ErrInvalidMapKey        = errors.New("invalid mapkey structure (missing key or nonce)")
)

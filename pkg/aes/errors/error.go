package errors

import "errors"

var (
	ErrInvalidKeySize     = errors.New("invalid key size (must be 16 or 32 bytes)")
	ErrCipherInit         = errors.New("failed to initialize AES cipher")
	ErrGCMInit            = errors.New("failed to initialize GCM")
	ErrKeyGeneration      = errors.New("failed to generate random key")
	ErrNonceGeneration    = errors.New("failed to generate random nonce")
	ErrDecryptionFailed   = errors.New("failed to decrypt data")
	ErrBase64DecodeFailed = errors.New("failed to decode base64 input")
)

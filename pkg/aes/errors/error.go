package errors

import "errors"

var (
	// Sentinel errors
	ErrInvalidKeySize  = errors.New("invalid key size (must be 16 or 32 bytes)")
	ErrCipherInit      = errors.New("failed to initialize AES cipher")
	ErrGCMInit         = errors.New("failed to initialize GCM")
	ErrKeyGeneration   = errors.New("failed to generate random key")
	ErrNonceGeneration = errors.New("failed to generate random nonce")
)

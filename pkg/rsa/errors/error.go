package errors

import "errors"

var (
	ErrNilPublicKey     = errors.New("public key is nil")
	ErrNilPrivateKey    = errors.New("private key is nil")
	ErrEncryptionFailed = errors.New("RSA encryption failed")
	ErrDecryptionFailed = errors.New("RSA decryption failed")
	ErrHashUnavailable  = errors.New("hash function is unavailable")
)

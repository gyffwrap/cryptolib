package errors

import "errors"

var (
	// General
	ErrInvalidPEM         = errors.New("invalid PEM block")
	ErrParseFailed        = errors.New("failed to parse key")
	ErrUnsupportedKey     = errors.New("unsupported key type")
	ErrInvalidMetadata    = errors.New("invalid metadata")
	ErrVersionMismatch    = errors.New("version mismatch")
	ErrUnsupportedAlgo    = errors.New("unsupported algorithm")
	ErrInvalidPayload     = errors.New("invalid encrypted payload format")
	ErrBase64DecodeFailed = errors.New("failed to decode base64")

	// Public key
	ErrNilPublicKey = errors.New("public key is nil")
	ErrNotRSAPublic = errors.New("provided key is not RSA public key")

	// Private key
	ErrNilPrivateKey = errors.New("private key is nil")
	ErrNotRSAPrivate = errors.New("provided key is not RSA private key")

	// RSA
	ErrRSAEncryptionFailed = errors.New("RSA encryption failed")
	ErrRSADecryptionFailed = errors.New("RSA decryption failed")

	// AES
	ErrAESKeyGenFailed     = errors.New("AES key generation failed")
	ErrAESNonceGenFailed   = errors.New("AES nonce generation failed")
	ErrAESInvalidKeySize   = errors.New("invalid AES key size")
	ErrAESDecryptionFailed = errors.New("AES decryption failed")
	ErrAESEncryptionFailed = errors.New("AES encryption failed")

	// Cipher/GCM
	ErrCipherInit       = errors.New("failed to init cipher")
	ErrGCMInit          = errors.New("failed to init GCM")
	ErrDecryptionFailed = errors.New("decryption failed")
	ErrEncryptionFailed = errors.New("encryption failed")
)

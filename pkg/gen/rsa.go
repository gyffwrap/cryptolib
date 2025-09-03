package gen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	cryptErr "github.com/gyffwrap/cryptolib/pkg/gen/errors"
)

type RSAResult struct {
	PrivateKey *rsa.PrivateKey
}

func GenerateRSAKeyPair(bits int) (*RSAResult, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", cryptErr.ErrKeyGenerationFailed, err)
	}
	return &RSAResult{PrivateKey: privateKey}, nil
}

func (r *RSAResult) PrivateKeyPKCS1() ([]byte, error) {
	if r.PrivateKey == nil {
		return nil, cryptErr.ErrNilPrivateKey
	}
	sn := x509.MarshalPKCS1PrivateKey(r.PrivateKey)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: sn,
	}), nil
}

func (r *RSAResult) PrivateKeyPKCS8() ([]byte, error) {
	if r.PrivateKey == nil {
		return nil, cryptErr.ErrNilPrivateKey
	}
	sn, err := x509.MarshalPKCS8PrivateKey(r.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", cryptErr.ErrKeyGenerationFailed, err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: sn,
	}), nil
}

func (r *RSAResult) PublicKeyPKCS1() ([]byte, error) {
	if r.PrivateKey == nil {
		return nil, cryptErr.ErrNilPrivateKey
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&r.PrivateKey.PublicKey),
	}), nil
}

func (r *RSAResult) PublicKeyPKIX() ([]byte, error) {
	if r.PrivateKey == nil {
		return nil, cryptErr.ErrNilPrivateKey
	}
	pubASN1, err := x509.MarshalPKIXPublicKey(&r.PrivateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", cryptErr.ErrKeyGenerationFailed, err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	}), nil
}

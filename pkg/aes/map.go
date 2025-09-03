package aes

import "encoding/base64"

type AESResult struct {
	Ciphertext []byte
	Key        []byte
	Nonce      []byte
}

func (r *AESResult) GetCiphertext() []byte {
	return r.Ciphertext
}

func (r *AESResult) GetKey() []byte {
	return r.Key
}

func (r *AESResult) GetNonce() []byte {
	return r.Nonce
}

func (r *AESResult) GetCiphertextBase64() string {
	return base64.StdEncoding.EncodeToString(r.Ciphertext)
}

func (r *AESResult) GetKeyBase64() string {
	return base64.StdEncoding.EncodeToString(r.Key)
}

func (r *AESResult) GetNonceBase64() string {
	return base64.StdEncoding.EncodeToString(r.Nonce)
}

package negotiator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"reflect"
	"testing"
)

func TestNegotiator_Roundtrip(t *testing.T) {
	// 1. Generate a new RSA key pair for the test
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// 2. Convert keys to PEM format
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// 3. Create Target and Receiver
	target, err := NewNegotiateTarget(publicKeyPEM)
	if err != nil {
		t.Fatalf("NewNegotiateTarget failed: %v", err)
	}

	receiver, err := NewNegotiateReceiver(privateKeyPEM)
	if err != nil {
		t.Fatalf("NewNegotiateReceiver failed: %v", err)
	}

	// 4. Define test data
	plaintext := []byte("this is a top secret message for the negotiator")
	userMeta := &UserMeta{
		Name:     "test-file.txt",
		MimeType: "text/plain",
	}

	// 5. Encrypt
	encryptedPayload, err := target.Encrypt256(plaintext, userMeta)
	if err != nil {
		t.Fatalf("Encrypt256 failed: %v", err)
	}

	// 6. Decrypt
	decryptedResult, err := receiver.DecryptHybrid(encryptedPayload)
	if err != nil {
		t.Fatalf("DecryptHybrid failed: %v", err)
	}

	// 7. Verify results
	if string(plaintext) != string(decryptedResult.Plain) {
		t.Errorf("Decrypted plaintext does not match original. Got '%s', want '%s'",
			string(decryptedResult.Plain), string(plaintext))
	}

	if !reflect.DeepEqual(*userMeta, decryptedResult.UserMeta) {
		t.Errorf("Decrypted user metadata does not match original. Got '%+v', want '%+v'",
			decryptedResult.UserMeta, *userMeta)
	}
}

func TestNegotiator_ErrorCases(t *testing.T) {
	t.Run("NewNegotiateTarget with bad key", func(t *testing.T) {
		_, err := NewNegotiateTarget([]byte("not a valid key"))
		if err == nil {
			t.Error("Expected an error for invalid public key PEM, but got nil")
		}
	})

	t.Run("NewNegotiateReceiver with bad key", func(t *testing.T) {
		_, err := NewNegotiateReceiver([]byte("not a valid key"))
		if err == nil {
			t.Error("Expected an error for invalid private key PEM, but got nil")
		}
	})

	t.Run("DecryptHybrid with bad payload", func(t *testing.T) {
		// Generate a valid receiver
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		privateKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		})
		receiver, _ := NewNegotiateReceiver(privateKeyPEM)

		_, err := receiver.DecryptHybrid("invalid.payload")
		if err == nil {
			t.Error("Expected an error for invalid payload, but got nil")
		}
	})
}

func TestNegotiator_DecryptHybrid_InvalidInputs(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	receiver, _ := NewNegotiateReceiver(privateKeyPEM)

	cases := []struct {
		name      string
		encrypted string
	}{
		{"empty string", ""},
		{"no dot separator", "justastring"},
		{"invalid base64 meta", "%%%not-base64%%%.payload"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := receiver.DecryptHybrid(c.encrypted)
			if err == nil {
				t.Errorf("Expected error for case %q, got nil", c.name)
			}
		})
	}
}

func TestNegotiator_DecryptHybrid_WithNilReceiver(t *testing.T) {
	var r *ReceiverNegotiate
	_, err := r.DecryptHybrid("anything")
	if err == nil {
		t.Error("Expected error for nil receiver, got nil")
	}
}

func TestNegotiator_DecryptHybrid_ManipulatedMeta(t *testing.T) {
	// 1. Generate RSA key pair
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	publicKeyBytes, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	target, _ := NewNegotiateTarget(publicKeyPEM)
	receiver, _ := NewNegotiateReceiver(privateKeyPEM)

	plaintext := []byte("super secret test")
	userMeta := &UserMeta{Name: "case.txt", MimeType: "text/plain"}

	// 2. Encrypt valid
	validEncrypted, _ := target.Encrypt256(plaintext, userMeta)

	// 3. Pecah meta & payload
	parts := splitOnce(validEncrypted, ".")
	metaJSON, _ := base64.StdEncoding.DecodeString(parts[0])

	var meta MetaData
	_ = json.Unmarshal(metaJSON, &meta)

	// CASE 1: Version mismatch
	meta.Version = 999
	manipulated := buildEncrypted(meta, parts[1])
	if _, err := receiver.DecryptHybrid(manipulated); err == nil {
		t.Error("expected error for version mismatch, got nil")
	}

	// CASE 2: Algo mismatch
	meta.Version = Version
	meta.Algo = "RSA-OAEP+AES-128-CBC"
	manipulated = buildEncrypted(meta, parts[1])
	if _, err := receiver.DecryptHybrid(manipulated); err == nil {
		t.Error("expected error for algo mismatch, got nil")
	}

	// CASE 3: Missing nonce
	meta.Algo = AlgoRSAAES256GCM
	meta.Nonce = []byte{}
	manipulated = buildEncrypted(meta, parts[1])
	if _, err := receiver.DecryptHybrid(manipulated); err == nil {
		t.Error("expected error for empty nonce, got nil")
	}

	// CASE 4: Corrupted ciphertext
	meta.Nonce = []byte("123456789012") // fake nonce just to pass check
	manipulated = buildEncrypted(meta, "!!!not-base64!!!")
	if _, err := receiver.DecryptHybrid(manipulated); err == nil {
		t.Error("expected error for corrupted ciphertext, got nil")
	}
}

// helper untuk rebuild encrypted string setelah meta dimodifikasi
func buildEncrypted(meta MetaData, payload string) string {
	metaJSON, _ := json.Marshal(meta)
	encodedMeta := base64.StdEncoding.EncodeToString(metaJSON)
	return encodedMeta + "." + payload
}

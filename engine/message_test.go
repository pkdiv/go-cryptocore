package engine

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestEncryptDecrypt_Success(t *testing.T) {
	key := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, 12) // GCM standard nonce size
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatal(err)
	}

	message := []byte("Hello, this is a secret message!")

	ciphertext, err := EncryptMessage(key, message, nonce)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	if bytes.Equal(ciphertext, message) {
		t.Error("ciphertext should not be equal to message")
	}

	decrypted, err := DecryptMessage(key, ciphertext, nonce)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted, message) {
		t.Errorf("decrypted message mismatch: got %s, want %s", decrypted, message)
	}
}

func TestEncrypt_InvalidKeySize(t *testing.T) {
	invalidKey := make([]byte, 10) // Invalid size
	nonce := make([]byte, 12)
	message := []byte("test")

	_, err := EncryptMessage(invalidKey, message, nonce)
	if err == nil {
		t.Error("expected error for invalid key size, got nil")
	}
}

func TestEncrypt_InvalidNonceSize(t *testing.T) {
	key := make([]byte, 32)
	invalidNonce := make([]byte, 8) // Invalid size for GCM
	message := []byte("test")

	_, err := EncryptMessage(key, message, invalidNonce)
	if err == nil {
		t.Error("expected error for invalid nonce size, got nil")
	} else if err.Error() != "invalid nonce size" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestDecrypt_AuthenticationFailure(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	message := []byte("top secret")

	ciphertext, err := EncryptMessage(key, message, nonce)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with ciphertext
	ciphertext[0] ^= 0xFF

	_, err = DecryptMessage(key, ciphertext, nonce)
	if err == nil {
		t.Error("expected error for tampered ciphertext, got nil")
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	io.ReadFull(rand.Reader, key1)
	io.ReadFull(rand.Reader, key2)

	nonce := make([]byte, 12)
	message := []byte("top secret")

	ciphertext, err := EncryptMessage(key1, message, nonce)
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptMessage(key2, ciphertext, nonce)
	if err == nil {
		t.Error("expected error for wrong decryption key, got nil")
	}
}

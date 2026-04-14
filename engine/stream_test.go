package engine

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestStreamEncryptionDecryption(t *testing.T) {
	tempDir := t.TempDir()
	inputPath := filepath.Join(tempDir, "input.txt")
	encryptedPath := filepath.Join(tempDir, "encrypted.bin")
	decryptedPath := filepath.Join(tempDir, "decrypted.txt")

	originalContent := []byte("This is a test stream that needs to be encrypted and then decrypted.")
	if err := os.WriteFile(inputPath, originalContent, 0644); err != nil {
		t.Fatalf("Failed to create input file: %v", err)
	}

	key := []byte("thisis32bitlongpassphraseimusing") // 32 bytes for AES-256

	// Test Encryption
	encryptedFile, err := os.Create(encryptedPath)
	if err != nil {
		t.Fatalf("Failed to create encrypted file: %v", err)
	}
	if err := EncryptStream(inputPath, encryptedFile, key); err != nil {
		t.Fatalf("EncryptStream failed: %v", err)
	}
	encryptedFile.Close()

	// Verify the encrypted file is different from input
	encryptedContent, err := os.ReadFile(encryptedPath)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}
	if bytes.Equal(encryptedContent, originalContent) {
		t.Errorf("Encrypted file content should not match original content")
	}

	// Test Decryption
	encryptedFileForRead, err := os.Open(encryptedPath)
	if err != nil {
		t.Fatalf("Failed to open encrypted file for reading: %v", err)
	}
	if err := DecryptStream(encryptedFileForRead, decryptedPath, key); err != nil {
		t.Fatalf("DecryptStream failed: %v", err)
	}
	encryptedFileForRead.Close()

	// Verify the decrypted file matches input
	decryptedContent, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(decryptedContent, originalContent) {
		t.Errorf("Decrypted content does not match original. Expected %q, got %q", originalContent, decryptedContent)
	}
}

func TestStreamEncryptionInvalidKey(t *testing.T) {
	tempDir := t.TempDir()
	inputPath := filepath.Join(tempDir, "input.txt")
	encryptedPath := filepath.Join(tempDir, "encrypted.bin")

	if err := os.WriteFile(inputPath, []byte("Test data"), 0644); err != nil {
		t.Fatalf("Failed to create input file: %v", err)
	}

	invalidKey := []byte("short") // Invalid key size for AES
	encryptedFile, err := os.Create(encryptedPath)
	if err != nil {
		t.Fatalf("Failed to create encrypted file: %v", err)
	}
	defer encryptedFile.Close()
	if err := EncryptStream(inputPath, encryptedFile, invalidKey); err == nil {
		t.Errorf("EncryptStream should have failed with invalid key size")
	}
}

func TestStreamEncryptionMissingFile(t *testing.T) {
	tempDir := t.TempDir()
	inputPath := filepath.Join(tempDir, "nonexistent.txt")
	encryptedPath := filepath.Join(tempDir, "encrypted.bin")

	key := []byte("thisis32bitlongpassphraseimusing")
	encryptedFile, err := os.Create(encryptedPath)
	if err != nil {
		t.Fatalf("Failed to create encrypted file: %v", err)
	}
	defer encryptedFile.Close()
	if err := EncryptStream(inputPath, encryptedFile, key); err == nil {
		t.Errorf("EncryptStream should have failed with nonexistent input file")
	}
}

func TestStreamDecryptionInvalidKey(t *testing.T) {
	tempDir := t.TempDir()
	inputPath := filepath.Join(tempDir, "input.txt")
	encryptedPath := filepath.Join(tempDir, "encrypted.bin")
	decryptedPath := filepath.Join(tempDir, "decrypted.txt")

	if err := os.WriteFile(inputPath, []byte("Test data"), 0644); err != nil {
		t.Fatalf("Failed to create input file: %v", err)
	}

	key := []byte("thisis32bitlongpassphraseimusing")
	encryptedFile, err := os.Create(encryptedPath)
	if err != nil {
		t.Fatalf("Failed to create encrypted file: %v", err)
	}
	if err := EncryptStream(inputPath, encryptedFile, key); err != nil {
		t.Fatalf("EncryptStream failed: %v", err)
	}
	encryptedFile.Close()

	invalidKey := []byte("short")
	encryptedFileForRead, err := os.Open(encryptedPath)
	if err != nil {
		t.Fatalf("Failed to open encrypted file for reading: %v", err)
	}
	defer encryptedFileForRead.Close()
	if err := DecryptStream(encryptedFileForRead, decryptedPath, invalidKey); err == nil {
		t.Errorf("DecryptStream should have failed with invalid key size")
	}
}

func TestStreamDecryptionMissingFile(t *testing.T) {
	tempDir := t.TempDir()
	decryptedPath := filepath.Join(tempDir, "decrypted.txt")

	key := []byte("thisis32bitlongpassphraseimusing")
	// For testing, we create an empty reader instead of a nonexistent file,
	// because DecryptStream expects an io.Reader, which fails when attempting to read IV.
	emptyReader := bytes.NewReader([]byte{})
	if err := DecryptStream(emptyReader, decryptedPath, key); err == nil {
		t.Errorf("DecryptStream should have failed with empty reader (cannot read IV)")
	}
}

func TestStreamLargeFile(t *testing.T) {
	tempDir := t.TempDir()
	inputPath := filepath.Join(tempDir, "large_input.bin")
	encryptedPath := filepath.Join(tempDir, "large_encrypted.bin")
	decryptedPath := filepath.Join(tempDir, "large_decrypted.bin")

	// Create a large file (1MB) to ensure io.Copy chunks work correctly
	size := 1024 * 1024
	f, err := os.Create(inputPath)
	if err != nil {
		t.Fatalf("Failed to create large file: %v", err)
	}
	defer f.Close()

	chunk := make([]byte, 1024)
	for i := range chunk {
		chunk[i] = byte(i % 256)
	}

	for i := 0; i < size/len(chunk); i++ {
		f.Write(chunk)
	}
	f.Close()

	key := []byte("thisis32bitlongpassphraseimusing")

	encryptedFile, err := os.Create(encryptedPath)
	if err != nil {
		t.Fatalf("Failed to create encrypted file: %v", err)
	}
	if err := EncryptStream(inputPath, encryptedFile, key); err != nil {
		t.Fatalf("EncryptStream failed for large file: %v", err)
	}
	encryptedFile.Close()

	encryptedFileForRead, err := os.Open(encryptedPath)
	if err != nil {
		t.Fatalf("Failed to open encrypted file for reading: %v", err)
	}
	if err := DecryptStream(encryptedFileForRead, decryptedPath, key); err != nil {
		t.Fatalf("DecryptStream failed for large file: %v", err)
	}
	encryptedFileForRead.Close()

	// Verify the decrypted file matches input
	originalContent, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatalf("Failed to read input file: %v", err)
	}
	decryptedContent, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(decryptedContent, originalContent) {
		t.Errorf("Decrypted content does not match original for large file")
	}
}

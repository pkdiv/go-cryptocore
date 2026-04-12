package kdf

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestArgon2idKeyDerivation_Success(t *testing.T) {
	password := "password123"
	params, err := Argon2idKeyDerivation(password)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(params.Kek) == 0 {
		t.Error("expected non-empty key")
	}

	if len(params.Salt) != 16 {
		t.Errorf("expected 16 byte salt, got %d", len(params.Salt))
	}

	if params.KeyLen != 32 {
		t.Errorf("expected default key length 32, got %d", params.KeyLen)
	}
}

func TestArgon2idKeyDerivation_Options(t *testing.T) {
	password := "password123"
	customTime := uint32(5)
	customMemory := uint32(128 * 1024)
	customThreads := uint8(8)
	customKeyLen := uint32(64)

	params, err := Argon2idKeyDerivation(password,
		WithTime(customTime),
		WithMemory(customMemory),
		WithThreads(customThreads),
		WithKeyLen(customKeyLen),
	)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if params.Time != customTime {
		t.Errorf("expected time %d, got %d", customTime, params.Time)
	}
	if params.Memory != customMemory {
		t.Errorf("expected memory %d, got %d", customMemory, params.Memory)
	}
	if params.Threads != customThreads {
		t.Errorf("expected threads %d, got %d", customThreads, params.Threads)
	}
	if params.KeyLen != customKeyLen {
		t.Errorf("expected keyLen %d, got %d", customKeyLen, params.KeyLen)
	}
	if len(params.Kek) != int(customKeyLen) {
		t.Errorf("expected key content length %d, got %d", customKeyLen, len(params.Kek))
	}
}

func TestArgon2idKeyDerivation_Correctness(t *testing.T) {
	password := "secure-password"
	params, err := Argon2idKeyDerivation(password)
	if err != nil {
		t.Fatalf("failed to derive key: %v", err)
	}

	expectedKey := argon2.IDKey(
		[]byte(password),
		params.Salt,
		params.Time,
		params.Memory,
		params.Threads,
		params.KeyLen,
	)

	if !bytes.Equal(params.Kek, expectedKey) {
		t.Error("derived key does not match reference implementation")
	}
}

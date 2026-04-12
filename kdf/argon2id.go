package kdf

import (
	"crypto/rand"

	"golang.org/x/crypto/argon2"
)

type Argon2idParams struct {
	Kek     []byte
	Salt    []byte
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
}

type Options func(*Argon2idParams)

func Argon2idKeyDerivation(password string, opts ...Options) (Argon2idParams, error) {

	kek := Argon2idParams{
		Time:    3,
		Memory:  64 * 1024,
		Threads: 4,
		KeyLen:  32,
	}

	for _, opt := range opts {
		opt(&kek)
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return kek, err
	}

	key := argon2.IDKey([]byte(password), salt, kek.Time, kek.Memory, kek.Threads, kek.KeyLen)

	kek.Kek = key
	kek.Salt = salt

	return kek, nil
}

func WithTime(time uint32) Options {
	return func(k *Argon2idParams) {
		k.Time = time
	}
}

func WithMemory(memory uint32) Options {
	return func(k *Argon2idParams) {
		k.Memory = memory
	}
}

func WithThreads(threads uint8) Options {
	return func(k *Argon2idParams) {
		k.Threads = threads
	}
}

func WithKeyLen(keyLen uint32) Options {
	return func(k *Argon2idParams) {
		k.KeyLen = keyLen
	}
}

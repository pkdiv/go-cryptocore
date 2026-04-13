package engine

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

func EncryptMessage(key []byte, message []byte, nonce []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(nonce) != aesgcm.NonceSize() {
		return nil, errors.New("invalid nonce size")
	}

	return aesgcm.Seal(nil, nonce, message, nil), nil

}

func DecryptMessage(key []byte, message []byte, nonce []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(nonce) != aesgcm.NonceSize() {
		return nil, errors.New("invalid nonce size")
	}

	return aesgcm.Open(nil, nonce, message, nil)

}

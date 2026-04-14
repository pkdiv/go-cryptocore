package engine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"os"
)

func EncryptStream(inputPath string, writer io.Writer, key []byte) error {

	inputFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return err
	}

	if _, err := writer.Write(iv); err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	stream := cipher.NewCTR(block, iv)
	if _, err := io.Copy(writer, cipher.StreamReader{
		S: stream,
		R: inputFile,
	}); err != nil {
		return err
	}

	return nil

}

func DecryptStream(reader io.Reader, outputPath string, key []byte) error {

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	iv := make([]byte, 16)
	if _, err := reader.Read(iv); err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	stream := cipher.NewCTR(block, iv)

	if _, err := io.Copy(outputFile, cipher.StreamReader{
		S: stream,
		R: reader,
	}); err != nil {
		return err
	}

	return nil

}

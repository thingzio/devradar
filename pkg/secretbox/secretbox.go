// Package secretbox encrypts small application secrets with AES-256-GCM.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	ciphertextPrefix = "enc:"
	keySize          = 32
)

// Seal returns an authenticated encrypted representation of plaintext. The key
// must be exactly 32 bytes.
func Seal(key, plaintext, additionalData []byte) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate secret nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, additionalData)
	return ciphertextPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// Open authenticates and decrypts a value produced by Seal.
func Open(key []byte, stored string, additionalData []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	encoded, encrypted := strings.CutPrefix(stored, ciphertextPrefix)
	if !encrypted {
		return nil, fmt.Errorf("secretbox value is not encrypted")
	}
	sealed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode secretbox value: %w", err)
	}
	if len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return nil, fmt.Errorf("secretbox ciphertext is too short")
	}
	nonce, ciphertext := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("authenticate secretbox value: %w", err)
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("secretbox key must be exactly %d bytes", keySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create secretbox cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create secretbox GCM: %w", err)
	}
	return gcm, nil
}

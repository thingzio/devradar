package tenant

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

// flashCipherPrefix marks a token-flash value as AES-GCM ciphertext. A value
// without it is stored plaintext (no key configured — acceptable for local dev),
// so reads can transparently handle both and a deployment can turn encryption on
// or off without a data migration.
const flashCipherPrefix = "enc:"

// encryptFlash returns an at-rest representation of a raw token. With a 32-byte
// key it returns "enc:" + base64(nonce||ciphertext) (AES-256-GCM); with a nil
// key it returns the plaintext unchanged.
func encryptFlash(key []byte, plaintext string) (string, error) {
	if len(key) == 0 {
		return plaintext, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("token flash cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("token flash gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("token flash nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return flashCipherPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// decryptFlash reverses encryptFlash. A value without the cipher prefix is
// returned as-is (it was stored plaintext). A prefixed value requires the key
// and authenticates the ciphertext; a missing key or a tampered value errors.
func decryptFlash(key []byte, stored string) (string, error) {
	rest, isEnc := strings.CutPrefix(stored, flashCipherPrefix)
	if !isEnc {
		return stored, nil
	}
	if len(key) == 0 {
		return "", fmt.Errorf("token flash is encrypted but no key is configured")
	}
	raw, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return "", fmt.Errorf("token flash decode: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("token flash cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("token flash gcm: %w", err)
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("token flash ciphertext too short")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("token flash open: %w", err)
	}
	return string(plaintext), nil
}

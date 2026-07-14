// Package authn provides authentication token primitives.
package authn

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// NewToken returns prefix followed by 256 bits of cryptographic randomness.
func NewToken(prefix string) (string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return prefix + hex.EncodeToString(random), nil
}

// HashToken returns the lowercase hexadecimal SHA-256 digest of raw.
func HashToken(raw string) string {
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

// NormalizeEmail trims surrounding whitespace and lowercases email.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

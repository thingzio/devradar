package tenant

import (
	"crypto/rand"
	"strings"
	"testing"
)

func TestFlashCrypt_RoundTripWithKey(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	const secret = "dr_deadbeefdeadbeefdeadbeefdeadbeef"

	stored, err := encryptFlash(key, secret)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !strings.HasPrefix(stored, flashCipherPrefix) {
		t.Fatalf("encrypted value should carry the cipher prefix, got %q", stored)
	}
	if strings.Contains(stored, secret) {
		t.Fatal("ciphertext must not contain the plaintext token")
	}

	got, err := decryptFlash(key, stored)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != secret {
		t.Fatalf("round-trip mismatch: got %q want %q", got, secret)
	}
}

func TestFlashCrypt_NoKeyIsPlaintext(t *testing.T) {
	const secret = "dr_plaintextfallback"
	stored, err := encryptFlash(nil, secret)
	if err != nil {
		t.Fatal(err)
	}
	if stored != secret {
		t.Fatalf("no key should store plaintext, got %q", stored)
	}
	// A plaintext (unprefixed) value decrypts as-is, even with a key present.
	got, err := decryptFlash(nil, stored)
	if err != nil || got != secret {
		t.Fatalf("plaintext read: got %q err %v", got, err)
	}
}

func TestFlashCrypt_TamperedCiphertextFails(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	stored, err := encryptFlash(key, "dr_secret")
	if err != nil {
		t.Fatal(err)
	}
	// Flip a character in the base64 body; GCM auth must reject it.
	tampered := stored[:len(stored)-1] + flippedLast(stored)
	if _, err := decryptFlash(key, tampered); err == nil {
		t.Fatal("tampered ciphertext must fail authentication")
	}
	// Encrypted value with no key available must error, not leak.
	if _, err := decryptFlash(nil, stored); err == nil {
		t.Fatal("encrypted value with no key must error")
	}
}

func flippedLast(s string) string {
	last := s[len(s)-1]
	if last == 'A' {
		return "B"
	}
	return "A"
}

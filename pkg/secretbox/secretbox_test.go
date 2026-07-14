package secretbox_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/thingzio/devradar/pkg/secretbox"
)

func TestSecretboxRoundTripAndAADBinding(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	aad := []byte("session-hash/account-id")
	sealed, err := secretbox.Seal(key, []byte("dr_secret"), aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !strings.HasPrefix(sealed, "enc:") || strings.Contains(sealed, "dr_secret") {
		t.Fatalf("sealed value exposes plaintext: %q", sealed)
	}
	opened, err := secretbox.Open(key, sealed, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(opened) != "dr_secret" {
		t.Fatalf("opened = %q, want dr_secret", opened)
	}
	if _, err := secretbox.Open(key, sealed, []byte("other-session/account-id")); err == nil {
		t.Fatal("cross-binding Open succeeded")
	}
	if _, err := secretbox.Open(bytes.Repeat([]byte{0x24}, 32), sealed, aad); err == nil {
		t.Fatal("wrong-key Open succeeded")
	}
	replacement := byte('A')
	if sealed[len(sealed)-1] == replacement {
		replacement = 'B'
	}
	tampered := sealed[:len(sealed)-1] + string(replacement)
	if _, err := secretbox.Open(key, tampered, aad); err == nil {
		t.Fatal("tampered Open succeeded")
	}
}

func TestSecretboxRequiresExactKeyAndEncryptedValues(t *testing.T) {
	for _, size := range []int{0, 1, 16, 31, 33} {
		key := bytes.Repeat([]byte{1}, size)
		if _, err := secretbox.Seal(key, []byte("secret"), nil); err == nil {
			t.Errorf("Seal accepted %d-byte key", size)
		}
		if _, err := secretbox.Open(key, "plaintext", nil); err == nil {
			t.Errorf("Open accepted %d-byte key", size)
		}
	}
	if _, err := secretbox.Open(bytes.Repeat([]byte{1}, 32), "plaintext", nil); err == nil {
		t.Fatal("plaintext value opened")
	}
}

func TestSecretboxUsesRandomNonce(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	first, err := secretbox.Seal(key, []byte("same"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := secretbox.Seal(key, []byte("same"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("two seals reused a nonce")
	}
}

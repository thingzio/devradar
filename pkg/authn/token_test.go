package authn_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/thingzio/devradar/pkg/authn"
)

func TestNewToken(t *testing.T) {
	raw, err := authn.NewToken("dr_")
	if err != nil || !strings.HasPrefix(raw, "dr_") || len(raw) != 67 {
		t.Fatalf("NewToken() = %q, %v", raw, err)
	}
	if authn.HashToken(raw) == raw {
		t.Fatal("hash must not equal raw token")
	}
	suffix := strings.TrimPrefix(raw, "dr_")
	decoded, err := hex.DecodeString(suffix)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("token suffix = %q, decoded length = %d, err = %v", suffix, len(decoded), err)
	}
	if canonical := hex.EncodeToString(decoded); suffix != canonical {
		t.Fatalf("token suffix = %q, want canonical lowercase hex %q", suffix, canonical)
	}
}

func TestHashToken(t *testing.T) {
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := authn.HashToken("abc"); got != want {
		t.Fatalf("HashToken() = %q, want %q", got, want)
	}
}

func TestNormalizeEmail(t *testing.T) {
	if got, want := authn.NormalizeEmail("  Person@Example.COM\t"), "person@example.com"; got != want {
		t.Fatalf("NormalizeEmail() = %q, want %q", got, want)
	}
}

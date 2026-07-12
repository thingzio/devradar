package attest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func ecdsaPublicKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestNewNilWhenUnconfigured(t *testing.T) {
	c, err := New(Policy{})
	if err != nil {
		t.Fatalf("unconfigured policy should not error: %v", err)
	}
	if c.Available() {
		t.Fatal("unconfigured client should not be Available")
	}
}

func TestNewNilWhenIdentitiesButNoTrustRoot(t *testing.T) {
	// Keyless identities configured, but no trusted root and TUF disabled: there
	// is nothing to trust, so the verifier is effectively disabled (nil), not an
	// error — ingest must degrade, never fail.
	c, err := New(Policy{Identities: []string{"https://github.com/acme/ci"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Available() {
		t.Fatal("no trust material → client should be unavailable")
	}
}

func TestNewWithPublicKeyIsAvailable(t *testing.T) {
	c, err := New(Policy{PublicKeys: [][]byte{ecdsaPublicKeyPEM(t)}})
	if err != nil {
		t.Fatalf("configuring a public key should succeed: %v", err)
	}
	if !c.Available() {
		t.Fatal("client with a trusted public key should be Available")
	}
}

func TestNewRejectsMalformedPublicKey(t *testing.T) {
	if _, err := New(Policy{PublicKeys: [][]byte{[]byte("not a pem")}}); err == nil {
		t.Fatal("malformed public key PEM should error at construction")
	}
}

func TestVerifyMalformedBundleErrors(t *testing.T) {
	c, err := New(Policy{PublicKeys: [][]byte{ecdsaPublicKeyPEM(t)}})
	if err != nil {
		t.Fatal(err)
	}
	// A completed-but-rejected check returns a failed Result; an unparseable
	// bundle cannot be checked at all, so it returns an error (ingest records it).
	if _, err := c.Verify(context.Background(), []byte("sbom"), "sha256:abc", []byte("{not-json")); err == nil {
		t.Fatal("malformed bundle should return an error")
	}
}

func TestDecodeDigest(t *testing.T) {
	got, err := decodeDigest("sha256:6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 32 {
		t.Fatalf("decoded digest len = %d, want 32", len(got))
	}
	if _, err := decodeDigest("sha256:zzzz"); err == nil {
		t.Fatal("invalid hex should error")
	}
}

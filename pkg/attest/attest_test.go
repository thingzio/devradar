package attest_test

import (
	"context"
	"errors"
	"testing"

	"github.com/thingzio/devradar/pkg/attest"
)

func TestPolicyConfigured(t *testing.T) {
	if (attest.Policy{}).Configured() {
		t.Fatal("empty policy should not be configured")
	}
	if !(attest.Policy{Identities: []string{"id"}}).Configured() {
		t.Fatal("policy with an identity should be configured")
	}
	if !(attest.Policy{PublicKeys: [][]byte{[]byte("pem")}}).Configured() {
		t.Fatal("policy with a public key should be configured")
	}
}

func TestPolicyVersionStableAndOrderIndependent(t *testing.T) {
	a := attest.Policy{Identities: []string{"a", "b"}, Issuers: []string{"x"}}
	b := attest.Policy{Identities: []string{"b", "a"}, Issuers: []string{"x"}}
	if a.Version() != b.Version() {
		t.Fatalf("policy version should be order-independent: %s vs %s", a.Version(), b.Version())
	}
	c := attest.Policy{Identities: []string{"a", "b"}, Issuers: []string{"y"}}
	if a.Version() == c.Version() {
		t.Fatal("policy version should change when trust inputs change")
	}
	if a.Version() == (attest.Policy{}).Version() {
		t.Fatal("configured and empty policies should differ")
	}
}

func TestFakeVerifierPaths(t *testing.T) {
	ctx := context.Background()

	// Error path.
	ferr := &attest.Fake{Err: errors.New("boom")}
	if _, err := ferr.Verify(ctx, nil, "sha256:x", nil); err == nil {
		t.Fatal("expected error from fake")
	}

	// Success path fills in the requested digest and records inputs.
	fok := &attest.Fake{Result: &attest.Result{Outcome: attest.ResultVerified, Mode: attest.ModeKeyless}}
	res, err := fok.Verify(ctx, []byte("sbom"), "sha256:abc", []byte("bundle"))
	if err != nil {
		t.Fatal(err)
	}
	if res.SubjectDigest != "sha256:abc" {
		t.Fatalf("fake should copy requested digest, got %q", res.SubjectDigest)
	}
	if fok.Calls != 1 || string(fok.LastBundle) != "bundle" || fok.LastDigest != "sha256:abc" {
		t.Fatalf("fake did not record inputs: %+v", fok)
	}
}

// Copyright 2026 Thingz LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
)

// publicGoodTrustedRoot loads the public sigstore trusted-root JSON fixture so
// tests can build a real *root.TrustedRoot without any network/TUF access.
func publicGoodTrustedRoot(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/trusted-root-public-good.json")
	if err != nil {
		t.Fatalf("read trusted-root fixture: %v", err)
	}
	return data
}

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

func TestNewRejectsIdentitiesWithoutIssuers(t *testing.T) {
	// A keyless policy with identities but no issuers is a configuration error:
	// a Fulcio SAN is not globally unique across OIDC issuers, so an identity
	// MUST be pinned to an issuer. This must fail loudly, not silently disable.
	_, err := New(Policy{
		Identities:  []string{"https://github.com/acme/ci"},
		TrustedRoot: []byte(`{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`),
	})
	if err == nil {
		t.Fatal("keyless identities with no issuers must error")
	}
	if !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("error should mention the missing issuer, got: %v", err)
	}
}

func TestNewNilWhenNoTrustMaterial(t *testing.T) {
	// Identities + issuers configured, but no trusted root and TUF disabled: there
	// is nothing to trust, so the verifier is effectively disabled (nil), not an
	// error — an unconfigured trust root is distinct from a broken policy. (The
	// server's own startup guard decides whether that's fatal; the constructor
	// just reports "nothing to trust".)
	c, err := New(Policy{
		Identities: []string{"https://github.com/acme/ci"},
		Issuers:    []string{"https://token.actions.githubusercontent.com"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Available() {
		t.Fatal("no trust material → client should be unavailable")
	}
}

func TestNewKeylessWithIssuersAndRootIsAvailable(t *testing.T) {
	// The A1/A2 regression guard: a well-formed keyless policy (identities +
	// issuers + a trusted root) must build a USABLE verifier. Before the fix, the
	// empty-issuer identity made New() error and keyless verification was dead.
	c, err := New(Policy{
		Identities:  []string{"https://github.com/acme/ci/.github/workflows/release.yml@refs/heads/main"},
		Issuers:     []string{"https://token.actions.githubusercontent.com"},
		TrustedRoot: publicGoodTrustedRoot(t),
	})
	if err != nil {
		t.Fatalf("well-formed keyless policy should build: %v", err)
	}
	if !c.Available() {
		t.Fatal("keyless policy with identities+issuers+root should be Available")
	}
	if len(c.identity) != 1 {
		t.Fatalf("expected 1 cert identity (1 SAN × 1 issuer), got %d", len(c.identity))
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

func TestEnforcePredicateFailsClosed(t *testing.T) {
	c := &Client{policy: Policy{PredicateTypes: []string{"https://cyclonedx.org/bom"}}}

	// A3 regression: a signature that verified but carries NO predicate (empty)
	// must be downgraded to failed — a trusted signer must not get a `verified`
	// badge for signing a non-SBOM blob.
	empty := &Result{Outcome: ResultVerified, PredicateType: ""}
	c.enforcePredicate(empty)
	if empty.Outcome != ResultFailed {
		t.Fatalf("empty predicate must fail closed, got %q", empty.Outcome)
	}

	// A predicate outside the allow-list must fail.
	wrong := &Result{Outcome: ResultVerified, PredicateType: "https://slsa.dev/provenance/v1"}
	c.enforcePredicate(wrong)
	if wrong.Outcome != ResultFailed {
		t.Fatalf("non-allow-listed predicate must fail, got %q", wrong.Outcome)
	}

	// An allow-listed SBOM predicate passes.
	ok := &Result{Outcome: ResultVerified, PredicateType: "https://cyclonedx.org/bom"}
	c.enforcePredicate(ok)
	if ok.Outcome != ResultVerified {
		t.Fatalf("allow-listed predicate should stay verified, got %q: %s", ok.Outcome, ok.FailureReason)
	}

	// An already-failed result is left untouched (no reason clobbering).
	failed := &Result{Outcome: ResultFailed, FailureReason: "signature invalid"}
	c.enforcePredicate(failed)
	if failed.Outcome != ResultFailed || failed.FailureReason != "signature invalid" {
		t.Fatalf("existing failure must be preserved, got %+v", failed)
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

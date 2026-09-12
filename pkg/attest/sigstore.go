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
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	sigsig "github.com/sigstore/sigstore/pkg/signature"
)

// verifierVersion identifies the verification stack for evidence records. Bumped
// when the sigstore-go dependency or verification semantics change.
const verifierVersion = "sigstore-go/v1.2.2"

// Client is the nil-safe, sigstore-go-backed Verifier. New returns nil when no
// trust policy is configured, so callers degrade gracefully (Claude pattern).
type Client struct {
	policy   Policy
	trusted  root.TrustedMaterialCollection
	identity []verify.PolicyOption // one WithCertificateIdentity per allowed identity (OR)
	haveKey  bool
}

// New builds a verifier from the trust policy. It returns nil (not an error) when
// the policy is unconfigured or the trust material cannot be assembled, so an
// unconfigured or misconfigured deployment simply leaves SBOMs 'unverified'
// rather than failing ingest. Configuration errors are surfaced via err for the
// operator's logs, but a nil client with a nil error is also valid ("disabled").
func New(policy Policy) (*Client, error) {
	if !policy.Configured() {
		return nil, nil
	}

	trusted, err := buildTrustedMaterial(policy)
	if err != nil {
		return nil, fmt.Errorf("attest: assemble trusted material: %w", err)
	}
	if len(trusted) == 0 {
		return nil, nil // nothing to trust → feature effectively disabled
	}

	c := &Client{policy: policy, trusted: trusted}

	// Keyless identities must be pinned to BOTH a SAN and an OIDC issuer: a Fulcio
	// SAN (e.g. a GitHub workflow ref) is not globally unique across issuers, so
	// matching a SAN without pinning the issuer would accept a certificate issued
	// under a different (attacker-influenced) OIDC provider. sigstore itself
	// refuses a certificate identity with no issuer criteria, so a keyless policy
	// with identities but no issuers is a configuration error, not a silent
	// no-op — surface it. Each allowed (SAN, issuer) pair is an independent
	// identity; sigstore matches if ANY pair matches (AND within a pair).
	if len(policy.Identities) > 0 && len(policy.Issuers) == 0 {
		return nil, fmt.Errorf("attest: keyless policy has identities but no issuers " +
			"(set DEVRADAR_ATTEST_ISSUERS); an identity must be pinned to an OIDC issuer")
	}
	for _, san := range policy.Identities {
		for _, issuer := range policy.Issuers {
			certID, err := verify.NewShortCertificateIdentity(issuer, "", san, "")
			if err != nil {
				return nil, fmt.Errorf("attest: build identity %q@%q: %w", san, issuer, err)
			}
			c.identity = append(c.identity, verify.WithCertificateIdentity(certID))
		}
	}
	c.haveKey = len(policy.PublicKeys) > 0
	return c, nil
}

// Available reports whether a usable verifier is configured (nil-safe).
func (c *Client) Available() bool { return c != nil && len(c.trusted) > 0 }

// Verify checks the bundle against the trust policy and binds it to the SBOM.
// It first attempts the strong sbom-bytes binding (the attestation signed the
// exact stored bytes); if the bundle's subject does not match the SBOM bytes it
// falls back to the image-digest binding (the attestation names the resolved
// image digest). A completed-but-rejected check returns a *Result with
// Outcome=ResultFailed and a reason; only an inability to run the check returns
// an error.
func (c *Client) Verify(_ context.Context, sbomBytes []byte, subjectDigest string, bundleJSON []byte) (*Result, error) {
	if !c.Available() {
		return nil, fmt.Errorf("attest: verifier not configured")
	}
	b := &bundle.Bundle{}
	if err := json.Unmarshal(bundleJSON, b); err != nil {
		return nil, fmt.Errorf("attest: parse bundle: %w", err)
	}

	mode, identityPolicies := c.identityPolicies(b)

	sev, err := verify.NewVerifier(c.trusted,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithObserverTimestamps(1),
		verify.WithTransparencyLog(1))
	if err != nil {
		return nil, fmt.Errorf("attest: build verifier: %w", err)
	}

	// Try the strong sbom-bytes binding first: the attestation subject is the
	// sha256 of the exact bytes we stored. The two bindings differ ONLY in the
	// artifact digest, so a signature/identity/tlog failure fails both identically
	// — the image-digest fallback can only ever *succeed* on the specific case
	// where the bytes differ but the claimed image digest matches. We therefore
	// keep the primary (sbom-bytes) failure reason when both fail, so the operator
	// sees the real cause rather than a misleading digest mismatch.
	sbomSum := sha256.Sum256(sbomBytes)
	res, primaryErr := sev.Verify(b, verify.NewPolicy(
		verify.WithArtifactDigest("sha256", sbomSum[:]), identityPolicies...))
	binding := BindingSBOMBytes
	if primaryErr != nil {
		// Strong binding failed. If the policy requires it, stop here — do not
		// accept the weaker image-digest binding.
		if c.policy.RequireSBOMBytes {
			//nolint:nilerr // a rejected verification is a recorded failed Result, not a Go error
			return c.failed(mode, binding, subjectDigest, bundleJSON, primaryErr.Error()), nil
		}
		digestBytes, derr := decodeDigest(subjectDigest)
		if derr != nil {
			//nolint:nilerr // primaryErr is surfaced as the failure reason, not returned
			return c.failed(mode, binding, subjectDigest, bundleJSON, primaryErr.Error()), nil
		}
		var fallbackErr error
		res, fallbackErr = sev.Verify(b, verify.NewPolicy(
			verify.WithArtifactDigest("sha256", digestBytes), identityPolicies...))
		if fallbackErr != nil {
			// Both failed → report the primary (sbom-bytes) reason; the fallback
			// fails for the same underlying cause unless it was a pure byte mismatch.
			//nolint:nilerr // recorded failed Result, not a Go error
			return c.failed(mode, binding, subjectDigest, bundleJSON, primaryErr.Error()), nil
		}
		binding = BindingImageDigest
	}

	out := c.result(mode, binding, subjectDigest, bundleJSON, res)
	c.enforcePredicate(out)
	return out, nil
}

// enforcePredicate applies the predicate-type allow-list to an otherwise-verified
// result — FAIL CLOSED. A valid signature only earns a `verified` outcome when it
// is over an in-toto statement whose predicate type is allow-listed. A
// signed-but-non-SBOM bundle (a plain DSSE/message signature, or a statement with
// no predicate type) leaves PredicateType == "": treating that as a pass would
// let a trusted signer (or holder of the trusted key) attest an arbitrary blob
// and have DevRadar brand the SBOM authentic. So an empty or non-allow-listed
// predicate is downgraded to a recorded failure, never a pass. Mutates out.
func (c *Client) enforcePredicate(out *Result) {
	if out.Outcome != ResultVerified {
		return
	}
	switch {
	case out.PredicateType == "":
		out.Outcome = ResultFailed
		out.FailureReason = "attestation carries no in-toto SBOM predicate (not an SBOM attestation)"
	case !c.policy.allowsPredicate(out.PredicateType):
		out.Outcome = ResultFailed
		out.FailureReason = fmt.Sprintf("predicate type %q not in allow-list", out.PredicateType)
	}
}

// identityPolicies picks key vs keyless based on the bundle's verification
// material and returns the policy options to apply. When the bundle carries a
// certificate we use the configured identities (keyless); otherwise we fall back
// to key verification if a public key is trusted.
func (c *Client) identityPolicies(b *bundle.Bundle) (mode string, opts []verify.PolicyOption) {
	if _, err := b.VerificationContent(); err == nil && len(c.identity) > 0 && bundleHasCertificate(b) {
		return ModeKeyless, c.identity
	}
	if c.haveKey {
		return ModeKey, []verify.PolicyOption{verify.WithKey()}
	}
	// Default to keyless identities (the Verify call will fail if unmatched).
	return ModeKeyless, c.identity
}

func (c *Client) result(mode, binding, subjectDigest string, envelope []byte, res *verify.VerificationResult) *Result {
	out := &Result{
		Outcome:         ResultVerified,
		Mode:            mode,
		Binding:         binding,
		SubjectDigest:   subjectDigest,
		VerifierVersion: verifierVersion,
		PolicyVersion:   c.policy.Version(),
		Envelope:        envelope,
	}
	if res.Statement != nil {
		out.PredicateType = res.Statement.GetPredicateType()
	}
	if res.Signature != nil && res.Signature.Certificate != nil {
		out.CertIdentity = res.Signature.Certificate.SubjectAlternativeName
		out.OIDCIssuer = res.Signature.Certificate.CertificateIssuer
	}
	if res.Signature != nil && res.Signature.PublicKeyID != nil {
		out.KeyID = hex.EncodeToString(*res.Signature.PublicKeyID)
	}
	if len(res.VerifiedTimestamps) > 0 {
		out.TransparencyLogRef = transparencyRef(res.VerifiedTimestamps)
	}
	return out
}

func (c *Client) failed(mode, binding, subjectDigest string, envelope []byte, reason string) *Result {
	return &Result{
		Outcome:         ResultFailed,
		Mode:            mode,
		Binding:         binding,
		SubjectDigest:   subjectDigest,
		VerifierVersion: verifierVersion,
		PolicyVersion:   c.policy.Version(),
		FailureReason:   reason,
		Envelope:        envelope,
	}
}

func buildTrustedMaterial(policy Policy) (root.TrustedMaterialCollection, error) {
	var trusted root.TrustedMaterialCollection
	if len(policy.TrustedRoot) > 0 {
		tr, err := root.NewTrustedRootFromJSON(policy.TrustedRoot)
		if err != nil {
			return nil, fmt.Errorf("trusted root JSON: %w", err)
		}
		trusted = append(trusted, tr)
	} else if policy.TUFEnabled {
		tr, err := root.FetchTrustedRoot()
		if err != nil {
			return nil, fmt.Errorf("fetch TUF trusted root: %w", err)
		}
		trusted = append(trusted, tr)
	}
	for _, pemBytes := range policy.PublicKeys {
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return nil, fmt.Errorf("decode public key PEM")
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("unsupported public key type %T (want ECDSA)", pub)
		}
		trusted = append(trusted, trustedPublicKey(key))
	}
	return trusted, nil
}

func trustedPublicKey(pk *ecdsa.PublicKey) *root.TrustedPublicKeyMaterial {
	return root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		v, err := sigsig.LoadECDSAVerifier(pk, crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return &nonExpiringVerifier{v}, nil
	})
}

// nonExpiringVerifier treats a configured public key as valid at any time (a
// bare cosign key has no validity window, unlike a Fulcio cert).
type nonExpiringVerifier struct{ sigsig.Verifier }

func (*nonExpiringVerifier) ValidAtTime(_ time.Time) bool { return true }

func bundleHasCertificate(b *bundle.Bundle) bool {
	vc, err := b.VerificationContent()
	if err != nil {
		return false
	}
	return vc.Certificate() != nil
}

func decodeDigest(subjectDigest string) ([]byte, error) {
	hexPart := subjectDigest
	if _, after, found := strings.Cut(subjectDigest, ":"); found {
		hexPart = after
	}
	return hex.DecodeString(hexPart)
}

func transparencyRef(ts []verify.TimestampVerificationResult) string {
	// The sigstore-go timestamp result exposes the observer type, source URI, and
	// the integrated timestamp — enough for an operator to locate the entry. Use
	// the first observed timestamp as the reference (the transparency-log
	// threshold is already enforced by WithTransparencyLog(1)).
	for _, t := range ts {
		ref := t.Type
		if t.URI != "" {
			ref += " " + t.URI
		}
		if !t.Timestamp.IsZero() {
			ref += " @" + t.Timestamp.UTC().Format(time.RFC3339)
		}
		if ref != "" {
			return strings.TrimSpace(ref)
		}
	}
	return ""
}

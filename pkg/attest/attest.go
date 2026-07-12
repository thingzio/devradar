// Package attest verifies sigstore/cosign attestations submitted alongside an
// SBOM and produces durable, auditable evidence of every verification decision.
//
// It is an OPTIONAL, nil-safe dependency in the style of pkg/claude: New returns
// nil when no trust policy is configured, Available() is nil-safe, and callers
// degrade to leaving an SBOM 'unverified' rather than failing ingest. DevRadar
// never pulls images — the bundle is submitted inline by the CI that produced
// the SBOM, so verification adds authenticity on top of determinism without any
// registry access.
//
// Unlike VEX (a tenant's unverified assertion), a verification Result is a
// DevRadar-performed cryptographic check: it records what was proven (signature,
// identity/issuer or key, transparency-log inclusion, and which subject binding
// held) so the decision can be explained and audited later.
package attest

import "context"

// Verification outcome values. These also map to devradar_sbom.verification_status
// (ResultVerified/ResultFailed) with StatusUnverified as the default when no
// attestation is supplied.
const (
	ResultVerified = "verified"
	ResultFailed   = "failed"

	StatusUnverified = "unverified"
)

// Verification modes, inferred from the bundle and constrained by policy.
const (
	ModeKeyless = "keyless" // Fulcio cert identity + OIDC issuer + Rekor
	ModeKey     = "key"     // configured cosign public key
)

// Subject bindings, in decreasing strength. SBOM-bytes binding proves the exact
// stored bytes were signed; image-digest binding proves only that the attestation
// names the resolved image digest.
const (
	BindingSBOMBytes   = "sbom-bytes"
	BindingImageDigest = "image-digest"
)

// Result is the structured evidence of one verification decision. Every field a
// human or auditor needs to understand "why verified/failed" is retained; the
// raw bundle is kept in Envelope for round-trip.
type Result struct {
	Outcome            string // ResultVerified | ResultFailed
	Mode               string // ModeKeyless | ModeKey
	Binding            string // BindingSBOMBytes | BindingImageDigest
	SubjectDigest      string // digest that was cryptographically bound (sha256:...)
	PredicateType      string // observed in-toto predicate type
	CertIdentity       string // Fulcio SAN (keyless)
	OIDCIssuer         string // OIDC issuer (keyless)
	KeyID              string // public-key fingerprint (key mode)
	TransparencyLogRef string // Rekor log index / entry UUID
	VerifierVersion    string // sigstore-go version applied
	PolicyVersion      string // hash of the trust policy applied
	FailureReason      string // populated when Outcome == ResultFailed
	Envelope           []byte // raw bundle, round-trippable for audit
}

// Verifier verifies an attestation bundle against a trust policy and binds it to
// an SBOM. sbomBytes are the exact stored SBOM bytes (for sbom-bytes binding);
// subjectDigest is the SBOM's resolved image digest (for image-digest binding);
// bundle is the raw sigstore bundle. A returned error means verification could
// not be performed (malformed bundle, verifier fault) — the caller records it as
// a failed result and never fails ingest. A completed check that did not pass is
// returned as a non-nil *Result with Outcome == ResultFailed and a FailureReason.
type Verifier interface {
	// Available reports whether the verifier is configured to verify anything.
	// Nil-safe implementations return false, so callers can guard uniformly.
	Available() bool
	Verify(ctx context.Context, sbomBytes []byte, subjectDigest string, bundle []byte) (*Result, error)
}

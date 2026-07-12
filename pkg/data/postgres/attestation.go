package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/thingzio/devradar/pkg/attest"
)

// SaveAttestation records one verification decision and updates the SBOM's
// denormalized verification_status in a single transaction, so the fast-path
// flag and the evidence row can never disagree. Scoped by tenantID on the SBOM
// update (application-level isolation). Idempotent: re-submitting the same SBOM +
// attestation under the same policy is a no-op (ON CONFLICT DO NOTHING on the
// natural key), and the status update is deterministic for that (sbom, result).
func (s *Store) SaveAttestation(ctx context.Context, tenantID, sbomID string, r *attest.Result) error {
	if r == nil {
		return fmt.Errorf("save attestation: nil result")
	}
	switch r.Outcome {
	case attest.ResultVerified, attest.ResultFailed:
	default:
		return fmt.Errorf("save attestation: invalid outcome %q", r.Outcome)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin attestation tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO devradar_sbom_attestation
			(sbom_id, tenant_id, result, mode, binding, subject_digest, predicate_type,
			 cert_identity, oidc_issuer, key_id, transparency_log_ref,
			 verifier_version, policy_version, failure_reason, envelope)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		ON CONFLICT (sbom_id, subject_digest, policy_version) DO NOTHING`,
		sbomID, tenantID, r.Outcome, r.Mode, r.Binding, r.SubjectDigest,
		nullStr(r.PredicateType), nullStr(r.CertIdentity), nullStr(r.OIDCIssuer),
		nullStr(r.KeyID), nullStr(r.TransparencyLogRef), r.VerifierVersion,
		r.PolicyVersion, nullStr(r.FailureReason), envelopeJSON(r.Envelope)); err != nil {
		return fmt.Errorf("insert attestation: %w", err)
	}

	// Reflect the outcome on the SBOM, deriving the denormalized flag from the
	// evidence row that is actually PERSISTED — not blindly from r.Outcome. The
	// INSERT above is ON CONFLICT DO NOTHING on (sbom_id, subject_digest,
	// policy_version): a re-verification under the same key keeps the original
	// evidence untouched. Setting the flag from r.Outcome there would let the
	// fast-path flag and the evidence row disagree (e.g. stored 'verified',
	// re-run 'failed' → flag flips to failed while the row still says verified).
	// Reading the flag back out of the evidence table keeps them in lockstep by
	// construction, for both the fresh-insert and the conflict-kept case.
	if _, err := tx.ExecContext(ctx, `
		UPDATE devradar_sbom sb SET verification_status = ev.result
		FROM devradar_sbom_attestation ev
		WHERE sb.id=$1 AND sb.tenant_id=$2
		  AND ev.sbom_id=$1 AND ev.subject_digest=$3 AND ev.policy_version=$4`,
		sbomID, tenantID, r.SubjectDigest, r.PolicyVersion); err != nil {
		return fmt.Errorf("update verification status: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit attestation: %w", err)
	}
	return nil
}

// GetVerificationStatus returns the denormalized verification_status for an
// SBOM (unverified | verified | failed), tenant-scoped. Used by ingest to report
// the STORED status of a pre-existing SBOM without re-verifying against
// possibly-different resubmitted bytes. ErrNotFound if not owned.
func (s *Store) GetVerificationStatus(ctx context.Context, tenantID, sbomID string) (string, error) {
	var status string
	err := s.db.QueryRowContext(ctx,
		`SELECT verification_status FROM devradar_sbom WHERE id=$1 AND tenant_id=$2`,
		sbomID, tenantID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get verification status: %w", err)
	}
	return status, nil
}

// GetAttestation returns the most recent verification evidence for an SBOM, or
// ErrNotFound when none exists. Tenant-scoped.
func (s *Store) GetAttestation(ctx context.Context, tenantID, sbomID string) (*Attestation, error) {
	var a Attestation
	var predicate, identity, issuer, keyID, logRef, reason sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT id, sbom_id, result, mode, binding, subject_digest, predicate_type,
		       cert_identity, oidc_issuer, key_id, transparency_log_ref,
		       verifier_version, policy_version, failure_reason, verified_at
		FROM devradar_sbom_attestation
		WHERE tenant_id=$1 AND sbom_id=$2
		ORDER BY verified_at DESC, id DESC
		LIMIT 1`, tenantID, sbomID).Scan(
		&a.ID, &a.SBOMID, &a.Result, &a.Mode, &a.Binding, &a.SubjectDigest,
		&predicate, &identity, &issuer, &keyID, &logRef,
		&a.VerifierVersion, &a.PolicyVersion, &reason, &a.VerifiedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get attestation: %w", err)
	}
	a.PredicateType = predicate.String
	a.CertIdentity = identity.String
	a.OIDCIssuer = issuer.String
	a.KeyID = keyID.String
	a.TransparencyLogRef = logRef.String
	a.FailureReason = reason.String
	return &a, nil
}

// envelopeJSON ensures the JSONB column always receives valid JSON. An empty
// envelope is stored as an empty JSON object rather than SQL NULL (column is NOT
// NULL), so audit reads never have to special-case a missing bundle.
func envelopeJSON(raw []byte) []byte {
	if len(raw) == 0 {
		return []byte(`{}`)
	}
	return raw
}

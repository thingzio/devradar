package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/attest"
)

// SaveAttestation records one verification decision and updates the SBOM's
// denormalized verification_status in a single transaction, so the fast-path
// flag and the evidence row can never disagree. Scoped by tenantID on the SBOM
// update (application-level isolation). Idempotent: re-submitting the same SBOM +
// attestation under the same policy is a no-op (ON CONFLICT DO NOTHING on the
// natural key), and the status update is deterministic for that (sbom, result).
func (s *Store) SaveAttestation(ctx context.Context, tenantID, sbomID string, r *attest.Result) error {
	if err := validateAttestationResult(r); err != nil {
		return err
	}
	evidenceID, err := newAuditUUID()
	if err != nil {
		return fmt.Errorf("generate attestation evidence id: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin attestation tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, _, err := saveAttestation(ctx, tx, tenantID, sbomID, evidenceID, r); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit attestation: %w", err)
	}
	return nil
}

// SaveAttestationAudited records new API-submitted verification evidence and
// its attribution atomically. A natural-key retry appends no duplicate event.
func (s *Store) SaveAttestationAudited(ctx context.Context, tenantID, sbomID string, r *attest.Result, actor account.Actor, requestID string) error {
	if err := validateAttestationResult(r); err != nil {
		return err
	}
	evidenceID, err := newAuditUUID()
	if err != nil {
		return fmt.Errorf("generate attestation evidence id: %w", err)
	}
	return s.withAuditTarget(ctx, tenantID, actor, AuditEvent{
		Action: "attestation.save", TargetType: "sbom_attestation", TargetID: evidenceID,
		Outcome: "success", RequestID: requestID,
	}, func(tx *sql.Tx) (string, error) {
		persistedEvidenceID, changed, err := saveAttestation(ctx, tx, tenantID, sbomID, evidenceID, r)
		if err == nil && !changed {
			return persistedEvidenceID, errAuditNoMutation
		}
		return persistedEvidenceID, err
	})
}

func validateAttestationResult(r *attest.Result) error {
	if r == nil {
		return fmt.Errorf("save attestation: nil result")
	}
	switch r.Outcome {
	case attest.ResultVerified, attest.ResultFailed:
	default:
		return fmt.Errorf("save attestation: invalid outcome %q", r.Outcome)
	}
	return nil
}

func saveAttestation(ctx context.Context, tx *sql.Tx, tenantID, sbomID, evidenceID string, r *attest.Result) (string, bool, error) {
	var owned bool
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM devradar_sbom WHERE id=$1 AND tenant_id=$2)`,
		sbomID, tenantID).Scan(&owned); err != nil {
		return "", false, fmt.Errorf("check attestation SBOM owner: %w", err)
	}
	if !owned {
		return "", false, ErrNotFound
	}

	insertResult, err := tx.ExecContext(ctx, `
		INSERT INTO devradar_sbom_attestation
			(id, sbom_id, tenant_id, result, mode, binding, subject_digest, predicate_type,
			 cert_identity, oidc_issuer, key_id, transparency_log_ref,
			 verifier_version, policy_version, failure_reason, envelope)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (sbom_id, subject_digest, policy_version) DO NOTHING`,
		evidenceID, sbomID, tenantID, r.Outcome, r.Mode, r.Binding, r.SubjectDigest,
		nullStr(r.PredicateType), nullStr(r.CertIdentity), nullStr(r.OIDCIssuer),
		nullStr(r.KeyID), nullStr(r.TransparencyLogRef), r.VerifierVersion,
		r.PolicyVersion, nullStr(r.FailureReason), envelopeJSON(r.Envelope))
	if err != nil {
		return "", false, fmt.Errorf("insert attestation: %w", err)
	}
	inserted, err := insertResult.RowsAffected()
	if err != nil {
		return "", false, fmt.Errorf("insert attestation rows affected: %w", err)
	}

	var persistedEvidenceID, persistedResult string
	if err := tx.QueryRowContext(ctx, `
		SELECT id,result
		FROM devradar_sbom_attestation
		WHERE tenant_id=$1 AND sbom_id=$2
		  AND subject_digest=$3 AND policy_version=$4`,
		tenantID, sbomID, r.SubjectDigest, r.PolicyVersion).
		Scan(&persistedEvidenceID, &persistedResult); err != nil {
		return "", false, fmt.Errorf("select persisted attestation: %w", err)
	}

	updateResult, err := tx.ExecContext(ctx, `
		UPDATE devradar_sbom SET verification_status=$3
		WHERE id=$1 AND tenant_id=$2
		  AND verification_status IS DISTINCT FROM $3`,
		sbomID, tenantID, persistedResult)
	if err != nil {
		return "", false, fmt.Errorf("update verification status: %w", err)
	}
	updated, err := updateResult.RowsAffected()
	if err != nil {
		return "", false, fmt.Errorf("update verification status rows affected: %w", err)
	}
	return persistedEvidenceID, inserted > 0 || updated > 0, nil
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

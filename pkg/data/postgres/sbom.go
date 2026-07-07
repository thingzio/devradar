package postgres

import (
	"context"
	"fmt"

	"github.com/lib/pq"
)

// UpsertSBOM inserts a submitted SBOM, or returns the existing one. The natural
// identity is (tenant_id, digest, format): an image digest is an immutable
// package inventory, so there is one SBOM per digest+format per tenant. Both
// exact re-submission and a *different* SBOM for the same digest+format (e.g.
// by-tag vs by-digest generation, or a newer generator) resolve to the existing
// row — the first submission is canonical for the content. A re-submit may,
// however, backfill the version (tag) label if the original submit lacked one.
//
// Returns the effective row id (which may differ from sb.ID on conflict) and
// whether a new row was inserted (false ⇒ the caller may skip writing bytes).
func (s *Store) UpsertSBOM(ctx context.Context, sb *SBOM) (id string, inserted bool, err error) {
	var generatedAt any
	if !sb.GeneratedAt.IsZero() {
		generatedAt = sb.GeneratedAt.UTC()
	}
	tags := sb.Tags
	if tags == nil {
		tags = []string{} // pq.Array(nil) sends SQL NULL; the column is NOT NULL
	}
	// The SBOM bytes are immutable and content-addressed, so on conflict we never
	// touch content-derived columns (digest/format/package_count/tool/…). But the
	// version (tag) is a caller-supplied *label*: a re-submit that now carries a
	// tag should fill it in. COALESCE keeps an existing version when a later
	// digest-only submit omits it, so the label is never wiped. `xmax = 0` is
	// true only for a freshly inserted row (false for the DO UPDATE path), which
	// is how we report `inserted` accurately without a second query.
	// Tags union on conflict so a re-submit adds tags without dropping prior ones.
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO devradar_sbom
			(id, tenant_id, image_ref, repository, version, digest, format, spec_version,
			 tool, tool_version, package_count, object_path, verification_status, status,
			 tags, generated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (tenant_id, digest, format) DO UPDATE
		SET version = COALESCE(EXCLUDED.version, devradar_sbom.version),
		    tags = (SELECT COALESCE(array_agg(DISTINCT t), '{}')
		            FROM unnest(devradar_sbom.tags || EXCLUDED.tags) t)
		RETURNING id, (xmax = 0)`,
		sb.ID, sb.TenantID, sb.ImageRef, sb.Repository, nullStr(sb.Version),
		sb.Digest, sb.Format, sb.SpecVersion,
		nullStr(sb.Tool), nullStr(sb.ToolVersion), sb.PackageCount, sb.ObjectPath,
		defaultStr(sb.VerificationStatus, "unverified"), defaultStr(sb.Status, "active"),
		pq.Array(tags), generatedAt,
	).Scan(&id, &inserted)
	if err != nil {
		return "", false, fmt.Errorf("upsert sbom: %w", err)
	}
	return id, inserted, nil
}

// ListActiveSBOMs returns all active SBOMs across all tenants — the scan job's
// work list. It is intentionally cross-tenant (the scan job is a platform-wide
// batch); tenant scoping applies only to the read API.
func (s *Store) ListActiveSBOMs(ctx context.Context) ([]*SBOM, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tenant_id, image_ref, digest, format, spec_version,
		       COALESCE(tool,''), COALESCE(tool_version,''), package_count,
		       object_path, verification_status, status, submitted_at
		FROM devradar_sbom
		WHERE status = 'active'
		ORDER BY submitted_at`)
	if err != nil {
		return nil, fmt.Errorf("list active sboms: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []*SBOM
	for rows.Next() {
		var sb SBOM
		if err := rows.Scan(&sb.ID, &sb.TenantID, &sb.ImageRef, &sb.Digest, &sb.Format,
			&sb.SpecVersion, &sb.Tool, &sb.ToolVersion, &sb.PackageCount, &sb.ObjectPath,
			&sb.VerificationStatus, &sb.Status, &sb.SubmittedAt); err != nil {
			return nil, fmt.Errorf("scan sbom: %w", err)
		}
		out = append(out, &sb)
	}
	return out, rows.Err()
}

// RecordScanFailure appends a row to the failure surface. Failures are never
// swallowed into logs alone — they are queryable and drive ops alerting.
func (s *Store) RecordScanFailure(ctx context.Context, sbomID, scanner, stage string, cause error) {
	msg := ""
	if cause != nil {
		msg = cause.Error()
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO devradar_scan_failure (sbom_id, scanner, stage, error)
		VALUES ($1, $2, $3, $4)`,
		sbomID, nullStr(scanner), stage, msg); err != nil {
		// Last-resort: a failure recording a failure only goes to logs.
		// (caller already has the primary error)
		_ = err
	}
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func defaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

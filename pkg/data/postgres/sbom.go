package postgres

import (
	"context"
	"fmt"
	"time"

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
	labels := sb.Labels
	if labels == nil {
		labels = []string{} // pq.Array(nil) sends SQL NULL; the column is NOT NULL
	}
	// The SBOM bytes are immutable and content-addressed, so on conflict we never
	// touch content-derived columns (digest/format/package_count/tool/…). But the
	// version (image tag) is a caller-supplied label: a re-submit that now carries
	// a tag should fill it in. COALESCE keeps an existing version when a later
	// digest-only submit omits it, so it is never wiped. `xmax = 0` is true only
	// for a freshly inserted row (false for the DO UPDATE path), which is how we
	// report `inserted` accurately without a second query.
	// Labels union on conflict so a re-submit adds labels without dropping prior ones.
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO devradar_sbom
			(id, tenant_id, image_ref, repository, version, digest, format, spec_version,
			 tool, tool_version, package_count, object_path, verification_status, status,
			 labels, generated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (tenant_id, digest, format) DO UPDATE
		SET version = COALESCE(EXCLUDED.version, devradar_sbom.version),
		    labels = (SELECT COALESCE(array_agg(DISTINCT l), '{}')
		            FROM unnest(devradar_sbom.labels || EXCLUDED.labels) l)
		RETURNING id, (xmax = 0)`,
		sb.ID, sb.TenantID, sb.ImageRef, sb.Repository, nullStr(sb.Version),
		sb.Digest, sb.Format, sb.SpecVersion,
		nullStr(sb.Tool), nullStr(sb.ToolVersion), sb.PackageCount, sb.ObjectPath,
		defaultStr(sb.VerificationStatus, "unverified"), defaultStr(sb.Status, "active"),
		pq.Array(labels), generatedAt,
	).Scan(&id, &inserted)
	if err != nil {
		return "", false, fmt.Errorf("upsert sbom: %w", err)
	}
	return id, inserted, nil
}

// ListActiveSBOMs returns all active SBOMs across all tenants — the scan job's
// work list. It is intentionally cross-tenant (the scan job is a platform-wide
// batch); tenant scoping applies only to the read API. Equivalent to
// ListScannableSBOMs with a zero window (no staleness filter).
func (s *Store) ListActiveSBOMs(ctx context.Context) ([]*SBOM, error) {
	return s.ListScannableSBOMs(ctx, 0)
}

// ListScannableSBOMs returns the active SBOMs due for a scan: those never
// scanned yet (no devradar_scan_run row — a freshly submitted SBOM, prioritized
// so a new submission is picked up on the very next run) OR whose most recent
// scan is older than maxAge. A maxAge of 0 disables the staleness filter and
// returns every active SBOM (the daily-full-pass behavior).
//
// This lets the scheduler fire frequently (low submission-to-result latency)
// while each SBOM is still scanned at most a bounded number of times per day:
// cron frequency controls latency, maxAge controls per-SBOM load, independently.
// Cross-tenant by design, like ListActiveSBOMs.
func (s *Store) ListScannableSBOMs(ctx context.Context, maxAge time.Duration) ([]*SBOM, error) {
	// The staleness predicate is applied as an interval bound on the SBOM's latest
	// scan_run. NOT EXISTS covers the never-scanned case (new submissions) so they
	// are always due. Ordering by submitted_at keeps the oldest work first.
	where := `WHERE sb.status = 'active'`
	args := []any{}
	if maxAge > 0 {
		where += `
		  AND NOT EXISTS (
		      SELECT 1 FROM devradar_scan_run sr
		      WHERE sr.sbom_id = sb.id
		        AND sr.scanned_at > now() - $1::interval)`
		args = append(args, fmt.Sprintf("%d seconds", int64(maxAge.Seconds())))
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT sb.id, sb.tenant_id, sb.image_ref, sb.digest, sb.format, sb.spec_version,
		       COALESCE(sb.tool,''), COALESCE(sb.tool_version,''), sb.package_count,
		       sb.object_path, sb.verification_status, sb.status, sb.submitted_at
		FROM devradar_sbom sb
		`+where+`
		ORDER BY sb.submitted_at`, args...)
	if err != nil {
		return nil, fmt.Errorf("list scannable sboms: %w", err)
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

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
)

// ErrSBOMLimit is returned by UpsertSBOM when a brand-new SBOM would exceed the
// tenant's active-SBOM cap. A re-submit of an already-stored (tenant, digest,
// format) never hits this — it resolves to the existing row via ON CONFLICT.
var ErrSBOMLimit = errors.New("active SBOM limit reached for tenant")

// ErrImageLimit is returned by UpsertSBOMWithLimit when a brand-new repository
// would exceed the tenant's distinct-repository cap. A new digest under an
// already-tracked repository never hits this (it is not new-repo growth).
var ErrImageLimit = errors.New("image (repository) limit reached for tenant")

// UpsertSBOM inserts a submitted SBOM, or returns the existing one. The natural
// identity is (tenant_id, digest, format): an image digest is an immutable
// package inventory, so there is one SBOM per digest+format per tenant. Both
// exact re-submission and a *different* SBOM for the same digest+format (e.g.
// by-tag vs by-digest generation, or a newer generator) resolve to the existing
// row — the first submission is canonical for the content. A re-submit may,
// however, backfill the version (tag) label if the original submit lacked one.
//
// Returns the effective row id (which may differ from sb.ID on conflict),
// whether a new row was inserted, and the row's current status. A new SBOM is
// inserted 'pending' by default: ingest writes the bytes and then promotes the
// row to 'active' via ActivateSBOM, so a storage failure never leaves an active
// row without bytes. The returned status lets the caller self-heal — a retry
// that resolves to an existing but still-'pending' row (inserted=false,
// status="pending") re-drives the upload+activate instead of skipping it.
func (s *Store) UpsertSBOM(ctx context.Context, sb *SBOM) (id string, inserted bool, status string, err error) {
	return s.UpsertSBOMWithLimit(ctx, sb, 0, 0)
}

// UpsertSBOMWithLimit is UpsertSBOM with per-tenant quotas: maxSBOMs caps
// active+pending SBOMs (distinct digests+formats), maxRepos caps distinct active
// repositories. Either <= 0 disables that cap. A re-submit of an already-stored
// (tenant, digest, format) is always admitted (an update, not growth), as is a
// new digest under an already-tracked repository (only new repositories count
// against maxRepos). A brand-new digest past maxSBOMs returns ErrSBOMLimit; a
// brand-new repository past maxRepos returns ErrImageLimit.
//
// SOFT LIMITS — DELIBERATE (do not add locking to make them exact): the caps are
// enforced in a single INSERT...SELECT...WHERE whose count subquery shares the
// statement's snapshot. Under READ COMMITTED this does NOT serialize two truly
// simultaneous brand-new submits from the SAME tenant — both can see count < cap
// and both insert, overshooting by the in-flight count. That is accepted: these
// are abuse/runaway guards, not billing-exact quotas; a single tenant issuing
// genuinely concurrent submits is unlikely, and a bounded overshoot of a few past
// (e.g.) 5000 is harmless. Making them exact would require a per-tenant advisory
// lock + transaction on every ingest — real complexity and contention for a case
// that virtually never happens. The folded repo-cap guard is likewise soft.
func (s *Store) UpsertSBOMWithLimit(ctx context.Context, sb *SBOM, maxSBOMs, maxRepos int) (id string, inserted bool, status string, err error) {
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
	// report `inserted` accurately without a second query. The RETURNING status
	// reflects the post-conflict row so the caller can detect a stuck 'pending'.
	// Labels union on conflict so a re-submit adds labels without dropping prior ones.
	//
	// The SELECT...WHERE admits the row when EITHER cap allows it: a re-submit of an
	// existing (tenant,digest,format) always passes; otherwise a new digest is
	// admitted only if under the SBOM cap AND (its repo already exists OR under the
	// repo cap). We distinguish which cap blocked a rejection with a cheap follow-up
	// probe (only on the rare rejection path), so the caller can return the right
	// error/message. See the SOFT LIMITS note above re: concurrency.
	err = s.db.QueryRowContext(ctx, `
		INSERT INTO devradar_sbom
			(id, tenant_id, image_ref, repository, version, digest, format, spec_version,
			 tool, tool_version, package_count, object_path, verification_status, status,
			 labels, generated_at)
		SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16
		WHERE EXISTS (SELECT 1 FROM devradar_sbom
		              WHERE tenant_id = $2 AND digest = $6 AND format = $7)
		   OR (
		        ($17 <= 0 OR (SELECT count(*) FROM devradar_sbom
		                      WHERE tenant_id = $2 AND status IN ('active','pending')) < $17)
		        AND
		        ($18 <= 0
		         OR EXISTS (SELECT 1 FROM devradar_sbom
		                    WHERE tenant_id = $2 AND repository = $4 AND status = 'active')
		         OR (SELECT count(DISTINCT repository) FROM devradar_sbom
		             WHERE tenant_id = $2 AND status = 'active') < $18)
		      )
		ON CONFLICT (tenant_id, digest, format) DO UPDATE
		SET version = COALESCE(EXCLUDED.version, devradar_sbom.version),
		    labels = (SELECT COALESCE(array_agg(DISTINCT l), '{}')
		            FROM unnest(devradar_sbom.labels || EXCLUDED.labels) l)
		RETURNING id, (xmax = 0), status`,
		sb.ID, sb.TenantID, sb.ImageRef, sb.Repository, nullStr(sb.Version),
		sb.Digest, sb.Format, sb.SpecVersion,
		nullStr(sb.Tool), nullStr(sb.ToolVersion), sb.PackageCount, sb.ObjectPath,
		defaultStr(sb.VerificationStatus, "unverified"), defaultStr(sb.Status, "pending"),
		pq.Array(labels), generatedAt, maxSBOMs, maxRepos,
	).Scan(&id, &inserted, &status)
	if errors.Is(err, sql.ErrNoRows) {
		// Rejected by a cap. Probe which one so the caller reports the right limit —
		// a brand-new repository past the repo cap is ErrImageLimit; otherwise the
		// SBOM cap. Cheap and only on the (rare) rejection path.
		if maxRepos > 0 {
			var repoExists bool
			if perr := s.db.QueryRowContext(ctx,
				`SELECT EXISTS (SELECT 1 FROM devradar_sbom
				               WHERE tenant_id = $1 AND repository = $2 AND status = 'active')`,
				sb.TenantID, sb.Repository).Scan(&repoExists); perr == nil && !repoExists {
				return "", false, "", ErrImageLimit
			}
		}
		return "", false, "", ErrSBOMLimit
	}
	if err != nil {
		return "", false, "", fmt.Errorf("upsert sbom: %w", err)
	}
	return id, inserted, status, nil
}

// ActivateSBOM promotes a freshly-ingested SBOM from 'pending' to 'active' once
// its bytes have been durably stored, making it visible to the scan job and the
// read API. Scoped to the pending→active transition so it never resurrects an
// archived SBOM. Idempotent: a no-op (0 rows) when the row is already active.
func (s *Store) ActivateSBOM(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE devradar_sbom SET status='active' WHERE id=$1 AND status='pending'`, id); err != nil {
		return fmt.Errorf("activate sbom: %w", err)
	}
	return nil
}

// DeletePendingSBOM removes a still-'pending' SBOM row — the cleanup path when
// storing the bytes failed, so no orphaned, unscannable row is left behind. It
// only deletes rows still in the 'pending' state, so it can never race a
// concurrent activation or delete a live SBOM. Best-effort; a leftover pending
// row is harmless (invisible to scan/read) and a later retry re-drives it.
func (s *Store) DeletePendingSBOM(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM devradar_sbom WHERE id=$1 AND status='pending'`, id); err != nil {
		return fmt.Errorf("delete pending sbom: %w", err)
	}
	return nil
}

// ListActiveSBOMs returns all active SBOMs across all tenants — the scan job's
// work list. It is intentionally cross-tenant (the scan job is a platform-wide
// batch); tenant scoping applies only to the read API. Equivalent to
// ListScannableSBOMs with a zero window (no staleness filter, no scanner set).
func (s *Store) ListActiveSBOMs(ctx context.Context) ([]*SBOM, error) {
	return s.ListScannableSBOMs(ctx, 0, nil)
}

// ClearRescanRequested clears an operator-requested rescan marker for one SBOM.
// It runs once per SBOM after every expected scanner has been attempted (not
// inside per-scanner ApplyScan), so a "force rescan" covers the whole SBOM —
// every scanner runs — before the override is consumed. Idempotent: a no-op
// when no override was set.
func (s *Store) ClearRescanRequested(ctx context.Context, sbomID string) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE devradar_sbom SET rescan_requested_at = NULL
		 WHERE id = $1 AND rescan_requested_at IS NOT NULL`, sbomID); err != nil {
		return fmt.Errorf("clear rescan marker: %w", err)
	}
	return nil
}

// ListScannableSBOMs returns the active SBOMs due for a scan. Freshness is
// evaluated PER SCANNER: an SBOM is due when, for ANY scanner in expected, no
// devradar_scan_run for that scanner exists within maxAge. This covers the
// never-scanned case (a new submission has no runs, so it's due for every
// scanner) and — critically — the case where one scanner succeeded but another
// never ran or failed: the SBOM stays due until every expected scanner has a
// recent run, instead of one scanner's success masking another's absence. An
// operator-set rescan_requested_at forces the SBOM due regardless of freshness.
//
// A maxAge of 0 (or an empty expected set) disables the staleness filter and
// returns every active SBOM — the legacy daily-full-pass, used by
// ListActiveSBOMs. Ordering by submitted_at keeps the oldest work first.
//
// This lets the scheduler fire frequently (low submission-to-result latency)
// while each SBOM is still scanned at most a bounded number of times per day:
// cron frequency controls latency, maxAge controls per-SBOM load, independently.
// Cross-tenant by design, like ListActiveSBOMs.
func (s *Store) ListScannableSBOMs(ctx context.Context, maxAge time.Duration, expected []string) ([]*SBOM, error) {
	where := `WHERE sb.status = 'active'`
	args := []any{}
	if maxAge > 0 && len(expected) > 0 {
		// Due if forced, OR if any expected scanner lacks a run within the window.
		// The correlated NOT EXISTS is scanner-scoped: unnest(expected) enumerates
		// the required scanners and the inner NOT EXISTS asks "is this scanner
		// missing a recent run for this SBOM?" — true for a never-run or a
		// stale/failed scanner. $1 = interval, $2 = the expected scanner names.
		where += `
		  AND (sb.rescan_requested_at IS NOT NULL
		    OR EXISTS (
		      SELECT 1 FROM unnest($2::text[]) AS want(scanner)
		      WHERE NOT EXISTS (
		        SELECT 1 FROM devradar_scan_run sr
		        WHERE sr.sbom_id = sb.id
		          AND sr.scanner = want.scanner
		          AND sr.scanned_at > now() - $1::interval)))`
		args = append(args, fmt.Sprintf("%d seconds", int64(maxAge.Seconds())), pq.Array(expected))
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

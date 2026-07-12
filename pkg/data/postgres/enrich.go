package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/thingzio/devradar/pkg/enrich"
)

// DistinctActiveCVEs returns every distinct CVE currently present in an active
// SBOM's findings, across all tenants — the target set for EPSS enrichment (a
// bounded query, not the full public corpus). Cross-tenant by design: enrichment
// is CVE-keyed reference data shared by everyone.
func (s *Store) DistinctActiveCVEs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT f.exposure
		FROM devradar_finding f
		JOIN devradar_sbom sb ON sb.id = f.sbom_id
		WHERE sb.status = 'active' AND f.exposure LIKE 'CVE-%'
		ORDER BY f.exposure`)
	if err != nil {
		return nil, fmt.Errorf("distinct cves: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []string
	for rows.Next() {
		var cve string
		if err := rows.Scan(&cve); err != nil {
			return nil, fmt.Errorf("scan cve: %w", err)
		}
		out = append(out, cve)
	}
	return out, rows.Err()
}

// EnrichmentFreshWithin reports whether any enrichment row was updated within the
// window — the cadence gate that keeps the scan job from re-fetching the
// daily-updating EPSS/KEV feeds on every ~15-min tick. An empty table (never
// enriched) is NOT fresh, so the first run always populates it.
func (s *Store) EnrichmentFreshWithin(ctx context.Context, within time.Duration) (bool, error) {
	var fresh bool
	if err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM devradar_cve_enrichment
		               WHERE updated_at > now() - $1::interval)`,
		fmt.Sprintf("%d seconds", int64(within.Seconds()))).Scan(&fresh); err != nil {
		return false, fmt.Errorf("enrichment freshness: %w", err)
	}
	return fresh, nil
}

// UpsertCVEEnrichment writes enrichment records, replacing prior values per CVE.
// CVEs not re-fetched keep their last-known values (a stale EPSS is acceptable —
// see the package doc).
//
// kevAuthoritative controls how the KEV flag is written. A KEV designation is a
// security-relevant signal, so it may only be CLEARED when the KEV catalog was
// authoritatively fetched this run (kevAuthoritative=true) — then a record's
// KEV=false means the CVE genuinely left the catalog. When false (a KEV feed
// outage that Fetch rode through on EPSS alone), every record carries a
// zero-value KEV=false that is NOT a real removal; writing it would silently wipe
// every stored KEV flag. In that case we preserve the prior flag (kev = prior OR
// incoming), so an outage never downgrades a KEV.
func (s *Store) UpsertCVEEnrichment(ctx context.Context, recs []enrich.Record, kevAuthoritative bool) error {
	if len(recs) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin enrichment tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// When KEV was NOT authoritatively fetched, never let an incoming false clear a
	// stored true: OR the prior value in, and PRESERVE kev_added (COALESCE). When it
	// WAS authoritative, take the fresh value verbatim so a genuine catalog removal
	// is honored — and clear kev_added to match (EXCLUDED.kev_added is NULL for a
	// de-listed CVE), so a stale "date added" never lingers on a no-longer-KEV row.
	kevSet := `kev = EXCLUDED.kev`
	kevAddedSet := `kev_added = EXCLUDED.kev_added`
	if !kevAuthoritative {
		kevSet = `kev = (devradar_cve_enrichment.kev OR EXCLUDED.kev)`
		kevAddedSet = `kev_added = COALESCE(EXCLUDED.kev_added, devradar_cve_enrichment.kev_added)`
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO devradar_cve_enrichment (cve, epss_score, epss_percentile, kev, kev_added, updated_at)
		VALUES ($1, $2, $3, $4, $5, now())
		ON CONFLICT (cve) DO UPDATE SET
			epss_score      = COALESCE(EXCLUDED.epss_score, devradar_cve_enrichment.epss_score),
			epss_percentile = COALESCE(EXCLUDED.epss_percentile, devradar_cve_enrichment.epss_percentile),
			`+kevSet+`,
			`+kevAddedSet+`,
			updated_at      = now()`)
	if err != nil {
		return fmt.Errorf("prepare enrichment upsert: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, r := range recs {
		var added any
		if r.KEVAdded != "" {
			added = r.KEVAdded
		}
		if _, err := stmt.ExecContext(ctx, r.CVE, nullFloat(r.EPSSScore), nullFloat(r.EPSSPercentile),
			r.KEV, added); err != nil {
			return fmt.Errorf("upsert enrichment %s: %w", r.CVE, err)
		}
	}
	return tx.Commit()
}

func nullFloat(f *float32) any {
	if f == nil {
		return nil
	}
	return *f
}

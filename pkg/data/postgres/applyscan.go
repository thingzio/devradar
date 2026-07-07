package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/thingzio/devradar/pkg/data"
)

// ApplyScan records the result of scanning one SBOM with one scanner. It is the
// delta engine: it diffs the incoming findings against the current stored state,
// writes only the changes to the append-only event log, updates current state,
// and records one scan_run summary — all in a single transaction.
//
// Every event is tagged with a cause (image | db | tooling) derived from which
// version axis changed since the previous run, so alerting can ignore changes
// the tenant didn't cause (a scanner upgrade must never page anyone).
//
// The method is idempotent by state convergence, not by the event UNIQUE
// constraint (which includes occurred_at = the run's wall clock, so it does NOT
// absorb a retry's re-fired events). A committed first run leaves devradar_finding
// holding the current state; a retry then recomputes the identical incoming set,
// finds changed()==false for every finding, and emits zero events. A retry that
// crashes before commit rolls back and writes nothing. So a Cloud Run Job retry
// is safe. (This holds for the serial single-worker scan job; concurrent runs of
// the same (sbom, scanner) are out of scope by design.)
func (s *Store) ApplyScan(ctx context.Context, sb *SBOM, scanner string, ver Versions, vulns []data.Vulnerability) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit

	prev, err := loadCurrentFindings(ctx, tx, sb.ID, scanner)
	if err != nil {
		return err
	}
	prevVer, err := loadPrevVersions(ctx, tx, sb.ID, scanner)
	if err != nil {
		return err
	}

	incoming := make(map[string]data.Vulnerability, len(vulns))
	for _, v := range vulns {
		incoming[v.GetID()] = v // dedup within a scan by identity
	}

	now := time.Now().UTC()
	runID, err := insertScanRun(ctx, tx, sb.ID, scanner, ver, now, vulns)
	if err != nil {
		return err
	}

	// Cause is a property of the run, not of any single finding: one set of
	// versions is being compared against one prior run, so every delta in this
	// scan shares the same cause.
	cause := classifyCause(ver, prevVer)

	// added / rerated / fixed
	for id, in := range incoming {
		old, existed := prev[id]
		switch {
		case !existed:
			if err := insertEvent(ctx, tx, sb, scanner, id, data.EventAdded, in, nil, cause, ver, runID, now); err != nil {
				return err
			}
			if err := upsertFinding(ctx, tx, sb.ID, scanner, id, in, now); err != nil {
				return err
			}
		case changed(old, in):
			evType := data.EventRerated
			if !old.IsFixed && in.IsFixed {
				evType = data.EventFixed
			}
			if err := insertEvent(ctx, tx, sb, scanner, id, evType, in, &old, cause, ver, runID, now); err != nil {
				return err
			}
			if err := upsertFinding(ctx, tx, sb.ID, scanner, id, in, now); err != nil {
				return err
			}
			// unchanged → no write (the common case; keeps the event log small)
		}
	}

	// resolved: in previous, not in incoming
	for id, old := range prev {
		if _, stillPresent := incoming[id]; stillPresent {
			continue
		}
		if err := insertEvent(ctx, tx, sb, scanner, id, data.EventResolved, old, &old, cause, ver, runID, now); err != nil {
			return err
		}
		if err := deleteFinding(ctx, tx, sb.ID, scanner, id); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// classifyCause attributes a run's deltas to the single version axis that
// changed since the prior run of this exact SBOM+scanner. Because the SBOM is
// immutable and keyed per digest, the first-ever run of an SBOM is image-caused
// (the image is the newest input); thereafter a changed vuln DB is db-caused and
// a changed scanner/canonicalizer is tooling-caused. Priority reflects which
// input is the more meaningful cause when more than one moved.
func classifyCause(ver, prev Versions) string {
	if prev == (Versions{}) {
		// No prior scan of this exact SBOM → the SBOM itself is what's new.
		return data.CauseImage
	}
	if prev.DBVersion != ver.DBVersion {
		return data.CauseDB
	}
	if prev.ScannerVersion != ver.ScannerVersion || prev.CanonicalizerVersion != ver.CanonicalizerVersion {
		return data.CauseTooling
	}
	// Same SBOM, same DB, same tooling — a delta here reflects real-world DB
	// movement the caller labeled identically; attribute to db, never image.
	return data.CauseDB
}

// changed reports whether a finding's mutable attributes differ.
func changed(a, b data.Vulnerability) bool {
	return a.Severity != b.Severity || a.Score != b.Score || a.IsFixed != b.IsFixed
}

// ── row helpers ───────────────────────────────────────────────────────────────

func loadCurrentFindings(ctx context.Context, tx *sql.Tx, sbomID, scanner string) (map[string]data.Vulnerability, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT finding_id, exposure, package, version, severity, score, is_fixed
		FROM devradar_finding WHERE sbom_id = $1 AND scanner = $2`, sbomID, scanner)
	if err != nil {
		return nil, fmt.Errorf("load findings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := map[string]data.Vulnerability{}
	for rows.Next() {
		var id string
		var v data.Vulnerability
		if err := rows.Scan(&id, &v.Exposure, &v.Package, &v.Version, &v.Severity, &v.Score, &v.IsFixed); err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		out[id] = v
	}
	return out, rows.Err()
}

// loadPrevVersions returns the version axes of the most recent prior scan run
// for this (sbom, scanner). Zero Versions if there is none.
func loadPrevVersions(ctx context.Context, tx *sql.Tx, sbomID, scanner string) (Versions, error) {
	var v Versions
	err := tx.QueryRowContext(ctx, `
		SELECT db_version, scanner_version, canonicalizer_version
		FROM devradar_scan_run WHERE sbom_id = $1 AND scanner = $2
		ORDER BY scanned_at DESC LIMIT 1`, sbomID, scanner).
		Scan(&v.DBVersion, &v.ScannerVersion, &v.CanonicalizerVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return Versions{}, nil
	}
	if err != nil {
		return Versions{}, fmt.Errorf("load prev versions: %w", err)
	}
	return v, nil
}

func insertScanRun(ctx context.Context, tx *sql.Tx, sbomID, scanner string, ver Versions, at time.Time, vulns []data.Vulnerability) (string, error) {
	var c, h, m, l int
	for _, v := range vulns {
		switch v.Severity {
		case data.SeverityCritical:
			c++
		case data.SeverityHigh:
			h++
		case data.SeverityMedium:
			m++
		case data.SeverityLow:
			l++
		}
	}
	var id string
	err := tx.QueryRowContext(ctx, `
		INSERT INTO devradar_scan_run
			(sbom_id, scanner, db_version, scanner_version, canonicalizer_version,
			 scanned_at, finding_count, critical_count, high_count, medium_count, low_count)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING id`,
		sbomID, scanner, ver.DBVersion, ver.ScannerVersion, ver.CanonicalizerVersion,
		at, len(vulns), c, h, m, l).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("insert scan_run: %w", err)
	}
	return id, nil
}

func insertEvent(ctx context.Context, tx *sql.Tx, sb *SBOM, scanner, findingID, evType string,
	cur data.Vulnerability, prev *data.Vulnerability, cause string, ver Versions, runID string, at time.Time) error {

	var prevSev any
	var prevScore any
	if prev != nil {
		prevSev = prev.Severity
		prevScore = prev.Score
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO devradar_finding_event
			(tenant_id, sbom_id, scanner, finding_id, event_type, exposure, package, version,
			 severity, score, prev_severity, prev_score, cause, db_version, scanner_version,
			 scan_run_id, occurred_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
		ON CONFLICT (sbom_id, scanner, finding_id, event_type, db_version, scanner_version, occurred_at)
		DO NOTHING`,
		sb.TenantID, sb.ID, scanner, findingID, evType, cur.Exposure, cur.Package, cur.Version,
		cur.Severity, cur.Score, prevSev, prevScore, cause, ver.DBVersion, ver.ScannerVersion,
		runID, at)
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}
	return nil
}

func upsertFinding(ctx context.Context, tx *sql.Tx, sbomID, scanner, findingID string, v data.Vulnerability, at time.Time) error {
	_, err := tx.ExecContext(ctx, `
		INSERT INTO devradar_finding
			(sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (sbom_id, scanner, finding_id) DO UPDATE SET
			severity = EXCLUDED.severity, score = EXCLUDED.score,
			is_fixed = EXCLUDED.is_fixed, updated_at = EXCLUDED.updated_at`,
		sbomID, scanner, findingID, v.Exposure, v.Package, v.Version, v.Severity, v.Score, v.IsFixed, at)
	if err != nil {
		return fmt.Errorf("upsert finding: %w", err)
	}
	return nil
}

func deleteFinding(ctx context.Context, tx *sql.Tx, sbomID, scanner, findingID string) error {
	_, err := tx.ExecContext(ctx, `
		DELETE FROM devradar_finding WHERE sbom_id = $1 AND scanner = $2 AND finding_id = $3`,
		sbomID, scanner, findingID)
	if err != nil {
		return fmt.Errorf("delete finding: %w", err)
	}
	return nil
}

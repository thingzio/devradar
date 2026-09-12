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

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/thingzio/devradar/pkg/data"
)

// sortedKeys returns a map's keys in ascending order, so a loop over a finding
// map emits events in a stable, reproducible sequence rather than Go's
// randomized map-iteration order.
func sortedKeys(m map[string]data.Vulnerability) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

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
// is safe.
//
// Concurrency: the read-modify-write of current state is serialized per
// (sbom, scanner) by a transaction-scoped advisory lock taken as the first
// statement. The scan job is single-worker by design, but Cloud Scheduler ticks
// and operator "force rescan" executions can overlap, and task retries can race
// a still-running task; the lock makes those safe rather than relying on the
// single-worker assumption. The lock auto-releases on commit/rollback.
func (s *Store) ApplyScan(ctx context.Context, sb *SBOM, scanner string, ver Versions, vulns []data.Vulnerability) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit

	// Serialize concurrent ApplyScan of the same (sbom, scanner): a per-key
	// transaction advisory lock. The two-key lock form takes the SBOM id and the
	// scanner name as independent 32-bit hashes (hashtext), so distinct pairs get
	// distinct locks without string concatenation. Held until this tx commits or
	// rolls back.
	if _, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))`, sb.ID, scanner); err != nil {
		return fmt.Errorf("acquire scan lock: %w", err)
	}

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

	// Read the run's timestamp from the database, not from this process. It is
	// compared against devradar_alert_policy.updated_at (stamped by the server's
	// clock) in alert.Match, and comparing two machines' clocks means any skew
	// silently suppresses alerts: an event that happened after a policy change
	// can carry an earlier timestamp and be treated as retroactive.
	//
	// clock_timestamp() rather than now(): now() is transaction-start time, and
	// this transaction blocks on the advisory lock above, so under contention
	// now() would backdate the run by the whole lock wait and reintroduce the
	// same suppression. Read once here and shared by every event in the run, so
	// the log stays as reproducible as it was with time.Now().
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return fmt.Errorf("read scan clock: %w", err)
	}
	now = now.UTC()

	runID, err := insertScanRun(ctx, tx, sb.ID, scanner, ver, now, vulns)
	if err != nil {
		return err
	}

	// Cause is a property of the run, not of any single finding: one set of
	// versions is being compared against one prior run, so every delta in this
	// scan shares the same cause.
	cause := classifyCause(ver, prevVer)

	// added / rerated / fixed. Iterate finding IDs in sorted order (not Go's
	// randomized map order) so that identical inputs produce the same event-id
	// sequence run-to-run — reproducibility of the append-only log, matching the
	// determinism guarantee. State convergence is order-independent, but a stable
	// order makes the event stream itself reproducible.
	for _, id := range sortedKeys(incoming) {
		in := incoming[id]
		old, existed := prev[id]
		switch {
		case !existed:
			eventID, err := insertEvent(ctx, tx, sb, scanner, id, data.EventAdded, in, nil, cause, ver, runID, now)
			if err != nil {
				return err
			}
			if err := enqueueAlertEvent(ctx, tx, sb.TenantID, eventID, cause, now); err != nil {
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
			eventID, err := insertEvent(ctx, tx, sb, scanner, id, evType, in, &old, cause, ver, runID, now)
			if err != nil {
				return err
			}
			if err := enqueueAlertEvent(ctx, tx, sb.TenantID, eventID, cause, now); err != nil {
				return err
			}
			if err := upsertFinding(ctx, tx, sb.ID, scanner, id, in, now); err != nil {
				return err
			}
			// unchanged → no write (the common case; keeps the event log small)
		}
	}

	// resolved: in previous, not in incoming (sorted, same reproducibility reason)
	for _, id := range sortedKeys(prev) {
		if _, stillPresent := incoming[id]; stillPresent {
			continue
		}
		old := prev[id]
		eventID, err := insertEvent(ctx, tx, sb, scanner, id, data.EventResolved, old, &old, cause, ver, runID, now)
		if err != nil {
			return err
		}
		if err := enqueueAlertEvent(ctx, tx, sb.TenantID, eventID, cause, now); err != nil {
			return err
		}
		if err := deleteFinding(ctx, tx, sb.ID, scanner, id); err != nil {
			return err
		}
	}

	// Refresh the per-SBOM severity rollup inside this transaction so it commits
	// atomically with the findings above and can never diverge on a crash. It
	// re-aggregates ALL scanners' rows for this SBOM (not just this scanner's), so
	// the two scanners of one scan each recompute the same converged value — the
	// second run is a no-op re-write, and if the second scanner fails the rollup
	// still reflects the committed state.
	if err := recomputeSBOMRollup(ctx, tx, sb.ID); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// RecomputeSBOMRollup rebuilds one SBOM's rollup row outside a scan transaction
// (its own statement on the pooled connection). ApplyScan maintains the rollup
// inline; this is the out-of-band repair/backfill entry point — e.g. after a
// bulk finding change made outside the scan path, or to reconcile a suspected
// drift. Idempotent and exact.
func (s *Store) RecomputeSBOMRollup(ctx context.Context, sbomID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin rollup tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := recomputeSBOMRollup(ctx, tx, sbomID); err != nil {
		return err
	}
	return tx.Commit()
}

// recomputeSBOMRollup rebuilds one SBOM's row in devradar_sbom_rollup from its
// current findings. Counts are RAW (no VEX suppression — that is applied at read
// time) and cross-scanner-deduped: COUNT(DISTINCT finding_id) collapses a CVE
// found by both grype and trivy to one, which is exactly COUNT(DISTINCT
// (sbom_id, finding_id)) scoped to this SBOM. Reads ~hundreds of PK-clustered
// rows; UPSERT keyed on sbom_id. KEV is overlaid from devradar_cve_enrichment
// (frozen at scan time, like the live read path).
func recomputeSBOMRollup(ctx context.Context, tx *sql.Tx, sbomID string) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO devradar_sbom_rollup (
			sbom_id, critical, high, medium, low, negligible, unknown, total,
			fixable, fix_critical, fix_high, fix_medium, fix_low, kev, updated_at)
		SELECT
			$1,
			COUNT(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'critical'),
			COUNT(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'high'),
			COUNT(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'medium'),
			COUNT(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'low'),
			COUNT(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'negligible'),
			COUNT(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'unknown'),
			COUNT(DISTINCT f.finding_id),
			COUNT(DISTINCT f.finding_id) FILTER (WHERE f.is_fixed),
			COUNT(DISTINCT f.finding_id) FILTER (WHERE f.is_fixed AND f.severity = 'critical'),
			COUNT(DISTINCT f.finding_id) FILTER (WHERE f.is_fixed AND f.severity = 'high'),
			COUNT(DISTINCT f.finding_id) FILTER (WHERE f.is_fixed AND f.severity = 'medium'),
			COUNT(DISTINCT f.finding_id) FILTER (WHERE f.is_fixed AND f.severity = 'low'),
			COUNT(DISTINCT f.exposure) FILTER (WHERE e.kev),
			now()
		FROM devradar_finding f
		LEFT JOIN devradar_cve_enrichment e ON e.cve = f.exposure
		WHERE f.sbom_id = $1
		ON CONFLICT (sbom_id) DO UPDATE SET
			critical = EXCLUDED.critical, high = EXCLUDED.high, medium = EXCLUDED.medium,
			low = EXCLUDED.low, negligible = EXCLUDED.negligible, unknown = EXCLUDED.unknown,
			total = EXCLUDED.total, fixable = EXCLUDED.fixable,
			fix_critical = EXCLUDED.fix_critical, fix_high = EXCLUDED.fix_high,
			fix_medium = EXCLUDED.fix_medium, fix_low = EXCLUDED.fix_low,
			kev = EXCLUDED.kev, updated_at = EXCLUDED.updated_at`, sbomID); err != nil {
		return fmt.Errorf("recompute rollup: %w", err)
	}
	return nil
}

// classifyCause attributes a run's deltas to the version axis that changed since
// the prior run of this exact SBOM+scanner. Because the SBOM is immutable and
// keyed per digest, the first-ever run of an SBOM is image-caused (the image is
// the newest input); thereafter a changed scanner/canonicalizer is tooling-caused
// and a changed vuln DB is db-caused.
//
// When MORE THAN ONE axis moved (a realistic deploy ships a new scanner binary
// together with a refreshed DB), tooling DOMINATES: the delta is treated as
// tooling (non-alertable) rather than db (alertable). This upholds the
// hard invariant that a scanner/canonicalizer upgrade must NEVER page a tenant —
// when a matcher-logic change is in the mix, its effect on the finding set is
// inseparable from the DB's, so we conservatively under-page (tooling) instead of
// risking a tooling-driven delta being alerted as db. A pure DB bump (tooling
// unchanged) is still correctly db-caused and alertable.
func classifyCause(ver, prev Versions) string {
	if prev == (Versions{}) {
		// No prior scan of this exact SBOM → the SBOM itself is what's new.
		return data.CauseImage
	}
	if prev.ScannerVersion != ver.ScannerVersion || prev.CanonicalizerVersion != ver.CanonicalizerVersion {
		// Tooling moved (possibly alongside the DB): classify as tooling so a
		// scanner upgrade can never page, even when the DB also changed.
		return data.CauseTooling
	}
	// Tooling held constant. A changed DB — or a delta under identical versions,
	// reflecting real-world DB movement the caller labeled the same — is db-caused.
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
	cur data.Vulnerability, prev *data.Vulnerability, cause string, ver Versions, runID string, at time.Time) (int64, error) {

	var prevSev any
	var prevScore any
	if prev != nil {
		prevSev = prev.Severity
		prevScore = prev.Score
	}
	var eventID int64
	err := tx.QueryRowContext(ctx, `
		INSERT INTO devradar_finding_event
			(tenant_id, sbom_id, scanner, finding_id, event_type, exposure, package, version,
			 severity, score, prev_severity, prev_score, cause, db_version, scanner_version,
			 scan_run_id, occurred_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
		ON CONFLICT (sbom_id, scanner, finding_id, event_type, db_version, scanner_version, occurred_at)
		DO NOTHING
		RETURNING id`,
		sb.TenantID, sb.ID, scanner, findingID, evType, cur.Exposure, cur.Package, cur.Version,
		cur.Severity, cur.Score, prevSev, prevScore, cause, ver.DBVersion, ver.ScannerVersion,
		runID, at).Scan(&eventID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("insert event: %w", err)
	}
	return eventID, nil
}

func enqueueAlertEvent(ctx context.Context, tx *sql.Tx, tenantID string, eventID int64, cause string, at time.Time) error {
	if eventID == 0 || (cause != data.CauseImage && cause != data.CauseDB) {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO devradar_alert_event_queue
			(consumer, tenant_id, event_occurred_at, event_id)
		VALUES ('browser-alerts-v1',$1,$2,$3)
		ON CONFLICT (consumer, event_occurred_at, event_id) DO NOTHING`,
		tenantID, at, eventID); err != nil {
		return fmt.Errorf("enqueue alert event: %w", err)
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

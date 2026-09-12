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
	"math"
	"time"
)

// Backoff tuning for a persistently-failing (SBOM, scanner) pair. The delay grows
// exponentially with the consecutive failure count and is capped; past a
// threshold the pair is quarantined and no longer auto-retried (an operator must
// reset it). These are deliberately conservative — a transient failure recovers
// on the next tick after a short delay, while a true poison input stops churning.
const (
	backoffBase         = 30 * time.Minute // delay after the first failure
	backoffMax          = 24 * time.Hour   // ceiling on the exponential delay
	backoffQuarantineAt = 8                // consecutive failures → quarantine
)

// backoffDelay returns the retry delay for the nth consecutive failure
// (base * 2^(n-1), capped at backoffMax). n <= 0 yields the base.
func backoffDelay(n int) time.Duration {
	if n <= 1 {
		return backoffBase
	}
	// Cap the shift so the multiplication can't overflow before the min().
	shift := min(n-1, 40)
	d := time.Duration(float64(backoffBase) * math.Pow(2, float64(shift)))
	if d <= 0 || d > backoffMax {
		return backoffMax
	}
	return d
}

// ScannerAttemptDue reports whether a (SBOM, scanner) pair may be attempted now:
// true when there is no backoff row (never failed, or last succeeded → row
// cleared), or the row is not quarantined and its next_attempt_at has passed.
// A quarantined pair is never due until an operator resets it.
func (s *Store) ScannerAttemptDue(ctx context.Context, sbomID, scanner string) (bool, error) {
	var quarantined bool
	var due bool
	err := s.db.QueryRowContext(ctx, `
		SELECT quarantined, (next_attempt_at <= now())
		FROM devradar_scan_attempt WHERE sbom_id = $1 AND scanner = $2`,
		sbomID, scanner).Scan(&quarantined, &due)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return true, nil // no backoff state → due
		}
		return false, fmt.Errorf("scanner attempt due: %w", err)
	}
	return !quarantined && due, nil
}

// RecordScannerAttemptFailure bumps the consecutive-failure count for a pair,
// schedules the next attempt with exponential backoff, and quarantines the pair
// once it crosses the threshold. Called in addition to RecordScanFailure (which
// keeps the queryable per-attempt failure log); this row is the retry-control
// state, one per pair, upserted.
func (s *Store) RecordScannerAttemptFailure(ctx context.Context, sbomID, scanner, errMsg string) error {
	// Read the current count to compute the new delay, then upsert. Done in one
	// statement via the ON CONFLICT expression referencing the prior fail_count.
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO devradar_scan_attempt (sbom_id, scanner, fail_count, quarantined, last_error, next_attempt_at, updated_at)
		VALUES ($1, $2, 1, (1 >= $3), $4, now() + $5::interval, now())
		ON CONFLICT (sbom_id, scanner) DO UPDATE SET
			fail_count      = devradar_scan_attempt.fail_count + 1,
			quarantined     = (devradar_scan_attempt.fail_count + 1 >= $3),
			last_error      = EXCLUDED.last_error,
			-- Recompute the delay from the NEW count. Postgres has no pow() on
			-- intervals, so the caller passes the base and we scale by 2^(n-1) via a
			-- generate_series-free expression: least(base * 2^(n-1), max).
			next_attempt_at = now() + LEAST(
				$6::interval * power(2, LEAST(devradar_scan_attempt.fail_count, 40)),
				$7::interval),
			updated_at      = now()`,
		sbomID, scanner, backoffQuarantineAt, truncateErr(errMsg),
		intervalSeconds(backoffDelay(1)),
		intervalSeconds(backoffBase), intervalSeconds(backoffMax)); err != nil {
		return fmt.Errorf("record scanner attempt failure: %w", err)
	}
	return nil
}

// ClearScannerAttempt removes any backoff state for a pair — called after a
// SUCCESSFUL scan so a recovered pair returns to the normal cadence immediately.
// Idempotent (no-op when no row exists, the steady state).
func (s *Store) ClearScannerAttempt(ctx context.Context, sbomID, scanner string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM devradar_scan_attempt WHERE sbom_id = $1 AND scanner = $2`,
		sbomID, scanner); err != nil {
		return fmt.Errorf("clear scanner attempt: %w", err)
	}
	return nil
}

func intervalSeconds(d time.Duration) string {
	return fmt.Sprintf("%d seconds", int64(d.Seconds()))
}

func truncateErr(s string) string {
	const max = 1000
	if len(s) > max {
		return s[:max]
	}
	return s
}

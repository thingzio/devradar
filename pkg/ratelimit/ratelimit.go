// Package ratelimit is a small, durable fixed-window rate limiter backed by
// Postgres (devradar_rate_event). It is deliberately boring: a per-key counter
// per time window, incremented atomically with an UPSERT. Because the state
// lives in the shared database, limits hold across Cloud Run instances and
// survive restarts — unlike an in-process token bucket.
//
// It is not a precise sliding window; a burst straddling a window boundary can
// briefly allow up to 2x the limit. That is an acceptable trade for the
// simplicity and durability, given the use cases (login/email abuse, token
// issuance) only need coarse protection.
package ratelimit

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Allow records one hit against key and reports whether it is within limit for
// the current window of length window. It buckets now() to the window start in
// SQL (so all instances agree on boundaries without a shared clock), UPSERTs the
// counter, and returns the post-increment count to decide admission. A DB error
// is returned to the caller, which should fail OPEN (allow) rather than lock
// users out on a transient database blip — that policy is the caller's choice,
// surfaced by returning (false, err) only on real over-limit vs (…, err) on
// failure.
//
// Returns allowed=true when the new count is <= limit.
func Allow(ctx context.Context, db queryRower, key string, limit int, window time.Duration) (bool, error) {
	if limit <= 0 {
		return true, nil // no limit configured
	}
	secs := int64(window.Seconds())
	if secs <= 0 {
		secs = 1
	}
	// window_start = to_timestamp(floor(extract(epoch from now())/secs)*secs).
	// The UPSERT increments an existing bucket or creates it at 1, and RETURNING
	// gives us the count after this hit.
	var count int
	err := db.QueryRowContext(ctx, `
		INSERT INTO devradar_rate_event (bucket_key, window_start, count)
		VALUES ($1, to_timestamp(floor(extract(epoch from now())/$2)*$2), 1)
		ON CONFLICT (bucket_key, window_start)
		DO UPDATE SET count = devradar_rate_event.count + 1
		RETURNING count`, key, secs).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("rate limit check: %w", err)
	}
	return count <= limit, nil
}

// Prune deletes rate windows older than the given age. Callers invoke it
// occasionally (e.g. best-effort after an allowed request) so the table stays
// small without a background job. Best-effort: errors are the caller's to log.
func Prune(ctx context.Context, db *sql.DB, olderThan time.Duration) error {
	secs := int64(olderThan.Seconds())
	if secs <= 0 {
		secs = 1
	}
	_, err := db.ExecContext(ctx,
		`DELETE FROM devradar_rate_event WHERE window_start < now() - ($1 || ' seconds')::interval`,
		fmt.Sprintf("%d", secs))
	if err != nil {
		return fmt.Errorf("prune rate events: %w", err)
	}
	return nil
}

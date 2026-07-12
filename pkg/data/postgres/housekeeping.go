package postgres

import (
	"context"
	"fmt"
)

// PurgeExpiredAuth reclaims dead ephemeral auth rows — expired login tokens and
// expired sessions — in one best-effort sweep. Both are already rejected at read
// time by an `expires_at > now()` guard (tenant.ValidateSession,
// tenant.ConsumeLoginToken), so deleting expired rows can never invalidate a live
// session or a still-usable link; it only stops the tables growing without bound.
//
// Run periodically off the scan job's end-of-run housekeeping (there is no cron).
// Returns the first error encountered but always attempts both deletes, so one
// failing table never blocks reclaiming the other. Kept as raw SQL here (rather
// than calling pkg/tenant) so the store owns all DDL/DML and there is no
// postgres↔tenant import edge.
func (s *Store) PurgeExpiredAuth(ctx context.Context) error {
	var firstErr error
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM devradar_login_token WHERE expires_at <= now()`); err != nil {
		firstErr = fmt.Errorf("purge login tokens: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM devradar_session WHERE expires_at <= now()`); err != nil {
		if firstErr == nil {
			firstErr = fmt.Errorf("purge sessions: %w", err)
		}
	}
	return firstErr
}

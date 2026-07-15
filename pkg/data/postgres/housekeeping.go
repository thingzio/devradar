package postgres

import (
	"context"
	"fmt"
)

// PurgeExpiredAuth reclaims dead ephemeral auth rows — expired login tokens,
// sessions, and one-time token-flash rows — in one best-effort sweep. All rows
// are already rejected at read time by an `expires_at > now()` guard, so deleting
// expired rows can never invalidate a live session, a still-usable link, or a
// still-displayable flash; it only stops the tables growing without bound.
//
// The token-flash sweep matters for more than table size. New session flashes
// contain only encrypted ciphertext, but old revisions may have written raw
// credentials to the retained compatibility table. Unread flashes would
// otherwise linger after their display window until overwritten or cascaded.
// Purging both formats bounds their retention to the flash TTL.
//
// Run periodically off the scan job's end-of-run housekeeping (there is no cron).
// Returns the first error encountered but always attempts every delete, so one
// failing table never blocks reclaiming the others. Kept as raw SQL here (rather
// than calling a separate compatibility package) so the store owns all DDL/DML and there is no
// postgres↔tenant import edge.
func (s *Store) PurgeExpiredAuth(ctx context.Context) error {
	var firstErr error
	record := func(err error, what string) {
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("purge %s: %w", what, err)
		}
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM devradar_login_token WHERE expires_at <= now()`)
	record(err, "login tokens")
	_, err = s.db.ExecContext(ctx, `DELETE FROM devradar_session WHERE expires_at <= now()`)
	record(err, "sessions")
	_, err = s.db.ExecContext(ctx, `DELETE FROM devradar_token_flash WHERE expires_at <= now()`)
	record(err, "legacy token flash")
	_, err = s.db.ExecContext(ctx, `DELETE FROM devradar_session_token_flash WHERE expires_at <= now()`)
	record(err, "session token flash")
	return firstErr
}

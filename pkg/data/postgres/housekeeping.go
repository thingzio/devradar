package postgres

import (
	"context"
	"fmt"
)

// PurgeExpiredAuth reclaims dead ephemeral auth rows — expired login tokens,
// sessions, and one-time token-flash rows — in one best-effort sweep. All three
// are already rejected at read time by an `expires_at > now()` guard, so deleting
// expired rows can never invalidate a live session, a still-usable link, or a
// still-displayable flash; it only stops the tables growing without bound.
//
// The token-flash sweep matters for MORE than table size: the flash row holds the
// RAW API token for one-time display, and when DEVRADAR_TOKEN_FLASH_KEY is not
// provisioned that value is stored in PLAINTEXT. A flash is normally deleted on
// read, but an UNREAD flash (the user closed the tab before viewing) would
// otherwise linger — with a usable plaintext credential — until the next token
// mint overwrites it or the tenant is deleted. Purging expired flash rows bounds
// that plaintext exposure to the flash TTL. (Provisioning the key to encrypt the
// value at rest is tracked in INFRA.md; this purge is the defense until then.)
//
// Run periodically off the scan job's end-of-run housekeeping (there is no cron).
// Returns the first error encountered but always attempts every delete, so one
// failing table never blocks reclaiming the others. Kept as raw SQL here (rather
// than calling pkg/tenant) so the store owns all DDL/DML and there is no
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
	record(err, "token flash")
	return firstErr
}

package tenant

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ErrSessionInvalid is returned when a session is missing or expired.
var ErrSessionInvalid = errors.New("session expired or not found")

// CreateSession generates a 256-bit token, stores its SHA-256 hash with a TTL,
// and returns the raw token for the cookie.
//
// Transitional: compatibility API until Task 4 moves the remaining
// tenant-auth callers to postgres.Store.
func CreateSession(ctx context.Context, db *sql.DB, tenantID string, ttl time.Duration) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	rawToken := hex.EncodeToString(raw)
	_, err := db.ExecContext(ctx,
		`INSERT INTO devradar_session (id, tenant_id, expires_at) VALUES ($1, $2, NOW() + $3::interval)`,
		HashToken(rawToken), tenantID, ttl.String())
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	return rawToken, nil
}

// ValidateSession returns the tenant for a valid, unexpired session token.
//
// Transitional: compatibility API until Task 4 moves the remaining
// tenant-auth callers to postgres.Store.
func ValidateSession(ctx context.Context, db *sql.DB, rawToken string) (*Tenant, error) {
	row := db.QueryRowContext(ctx, `
		SELECT `+prefixed("t")+`
		FROM devradar_session s JOIN devradar_tenant t ON t.id = s.tenant_id
		WHERE s.id = $1 AND s.expires_at > NOW()`, HashToken(rawToken))
	t, err := scanTenant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSessionInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("validate session: %w", err)
	}
	return t, nil
}

// DestroySession removes a session by its raw token (logout).
//
// Transitional: compatibility API until Task 4 moves the remaining
// tenant-auth callers to postgres.Store.
func DestroySession(ctx context.Context, db *sql.DB, rawToken string) error {
	if _, err := db.ExecContext(ctx, `DELETE FROM devradar_session WHERE id = $1`, HashToken(rawToken)); err != nil {
		return fmt.Errorf("destroy session: %w", err)
	}
	return nil
}

// PurgeExpiredSessions deletes sessions whose TTL has passed (best-effort
// housekeeping). Expired sessions are already rejected by ValidateSession's
// `expires_at > NOW()` guard, so this only reclaims dead rows — it can never log
// out a live session. Mirrors PurgeExpiredLoginTokens.
//
// Transitional: compatibility API; postgres.Store owns auth
// housekeeping.
func PurgeExpiredSessions(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `DELETE FROM devradar_session WHERE expires_at <= NOW()`); err != nil {
		return fmt.Errorf("purge expired sessions: %w", err)
	}
	return nil
}

// prefixed returns the tenant column list qualified with a table alias. Must
// match tenantColumns' order (scanTenant depends on it).
func prefixed(a string) string {
	return a + `.id, ` + a + `.email, ` + a + `.email_verified_at, ` + a + `.plan, ` +
		a + `.status, ` + a + `.min_severity, ` + a + `.avatar_url, ` + a + `.tos_accepted_at, ` +
		a + `.created_at, ` + a + `.updated_at`
}

package tenant

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrLoginTokenInvalid is returned for an unknown, expired, or already-used
// magic-link token.
var ErrLoginTokenInvalid = errors.New("login link invalid or expired")

// NormalizeEmail trims and lowercases an address so the same mailbox maps to one
// tenant regardless of how it was typed.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// CreateLoginToken issues a single-use magic-link token for email, stores only
// its hash with a TTL, and returns the raw token for the emailed link. The email
// is not required to belong to an existing tenant — first successful consume
// creates the tenant (sign-up and sign-in are the same flow).
func CreateLoginToken(ctx context.Context, db *sql.DB, email string, ttl time.Duration) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate login token: %w", err)
	}
	rawToken := hex.EncodeToString(raw)
	if _, err := db.ExecContext(ctx,
		`INSERT INTO devradar_login_token (id, email, expires_at)
		 VALUES ($1, $2, now() + $3::interval)`,
		HashToken(rawToken), NormalizeEmail(email), ttl.String()); err != nil {
		return "", fmt.Errorf("create login token: %w", err)
	}
	return rawToken, nil
}

// ConsumeLoginToken validates a raw magic-link token and, on success, upserts +
// verifies the tenant and returns it. The token is single-use: it is deleted
// atomically as part of consumption, so a link works at most once. Returns
// ErrLoginTokenInvalid if unknown, expired, or already used.
func ConsumeLoginToken(ctx context.Context, db *sql.DB, rawToken string) (*Tenant, error) {
	// Delete-and-return: the DELETE both enforces single-use and yields the email
	// only if the row existed and had not expired.
	var email string
	err := db.QueryRowContext(ctx, `
		DELETE FROM devradar_login_token
		WHERE id = $1 AND expires_at > now()
		RETURNING email`, HashToken(rawToken)).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrLoginTokenInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("consume login token: %w", err)
	}
	return UpsertTenantByEmail(ctx, db, email)
}

// PurgeExpiredLoginTokens deletes expired tokens (best-effort housekeeping).
func PurgeExpiredLoginTokens(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `DELETE FROM devradar_login_token WHERE expires_at <= now()`)
	return err
}

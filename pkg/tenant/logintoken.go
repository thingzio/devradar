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

// ErrLoginTokenInvalid is returned for an unknown or already-used magic-link
// token (no matching row).
var ErrLoginTokenInvalid = errors.New("login link invalid or already used")

// ErrLoginTokenExpired is returned when the token exists but its TTL has passed.
// Distinguished from ErrLoginTokenInvalid so the UI can tell a user whose link
// timed out ("request a new one") apart from a link that was already consumed
// (often an email-security scanner pre-fetching it — see the confirm-page flow).
var ErrLoginTokenExpired = errors.New("login link expired")

// NormalizeEmail trims and lowercases an address so the same mailbox maps to one
// tenant regardless of how it was typed.
//
// Transitional: compatibility API until Task 4 moves the remaining
// tenant-auth callers to authn.NormalizeEmail.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// CreateLoginToken issues a single-use magic-link token for email, stores only
// its hash with a TTL, and returns the raw token for the emailed link. The email
// is not required to belong to an existing tenant — first successful consume
// creates the tenant (sign-up and sign-in are the same flow).
//
// Transitional: compatibility API until Task 4 moves the remaining
// tenant-auth callers to postgres.Store.
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

// PeekLoginToken reports whether a raw token is currently valid (exists and not
// expired) WITHOUT consuming it. It backs the GET /auth/verify confirm page, so
// an email-security scanner pre-fetching the link cannot burn the single-use
// token — only the subsequent human POST consumes it. Returns the target email
// on success, ErrLoginTokenExpired if the row exists but timed out, or
// ErrLoginTokenInvalid if there is no such token (unknown or already consumed).
//
// Transitional: compatibility API until Task 4 moves the remaining
// tenant-auth callers to postgres.Store.
func PeekLoginToken(ctx context.Context, db *sql.DB, rawToken string) (email string, err error) {
	var expired bool
	err = db.QueryRowContext(ctx, `
		SELECT email, (expires_at <= now()) AS expired
		FROM devradar_login_token
		WHERE id = $1`, HashToken(rawToken)).Scan(&email, &expired)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrLoginTokenInvalid
	}
	if err != nil {
		return "", fmt.Errorf("peek login token: %w", err)
	}
	if expired {
		return "", ErrLoginTokenExpired
	}
	return email, nil
}

// ConsumeLoginToken validates a raw magic-link token and, on success, upserts +
// verifies the tenant and returns it. The token is single-use: it is deleted
// atomically as part of consumption, so a link works at most once. Distinguishes
// ErrLoginTokenExpired (row present but timed out) from ErrLoginTokenInvalid
// (unknown or already used) so callers can give the right guidance.
//
// Transitional: compatibility API until Task 4 moves the remaining
// tenant-auth callers to postgres.Store.
func ConsumeLoginToken(ctx context.Context, db *sql.DB, rawToken string) (*Tenant, error) {
	// Delete-and-return: the DELETE both enforces single-use and yields the email
	// only if the row existed and had not expired.
	var email string
	err := db.QueryRowContext(ctx, `
		DELETE FROM devradar_login_token
		WHERE id = $1 AND expires_at > now()
		RETURNING email`, HashToken(rawToken)).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		// No row deleted: either the token never existed / was already used, or it
		// exists but is expired. Disambiguate for a precise error (a second cheap
		// lookup; the common path — a valid token — never reaches here).
		var expired bool
		derr := db.QueryRowContext(ctx,
			`SELECT (expires_at <= now()) FROM devradar_login_token WHERE id = $1`,
			HashToken(rawToken)).Scan(&expired)
		if derr == nil && expired {
			return nil, ErrLoginTokenExpired
		}
		return nil, ErrLoginTokenInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("consume login token: %w", err)
	}
	// Route through the same identity spine as OAuth: a consumed magic link is a
	// verified-email proof, modeled as a ('magiclink', email) identity so the
	// identity table is a complete record of every sign-in method.
	return ResolveByIdentity(ctx, db, ProviderMagicLink, email, email, "")
}

// PurgeExpiredLoginTokens deletes expired tokens (best-effort housekeeping).
//
// Transitional: compatibility API; postgres.Store owns auth
// housekeeping.
func PurgeExpiredLoginTokens(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `DELETE FROM devradar_login_token WHERE expires_at <= now()`)
	return err
}

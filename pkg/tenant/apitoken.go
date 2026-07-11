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

// tokenPrefix identifies DevRadar API tokens (as devtrace uses "dt_").
const tokenPrefix = "dr_"

// ErrTokenInvalid is returned for an unknown or revoked API token.
var ErrTokenInvalid = errors.New("invalid or revoked API token")

// APITokenInfo is a token's metadata (never the secret).
type APITokenInfo struct {
	ID        string
	Name      string
	LastUsed  *time.Time
	CreatedAt time.Time
}

// CreateAPIToken generates a "dr_"-prefixed token, stores only its SHA-256 hash,
// and returns the raw token — shown to the user once, never persisted.
func CreateAPIToken(ctx context.Context, db *sql.DB, tenantID, name string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate api token: %w", err)
	}
	rawToken := tokenPrefix + hex.EncodeToString(raw)
	if _, err := db.ExecContext(ctx,
		`INSERT INTO devradar_api_token (tenant_id, name, token_hash) VALUES ($1, $2, $3)`,
		tenantID, name, HashToken(rawToken)); err != nil {
		return "", fmt.Errorf("create api token: %w", err)
	}
	return rawToken, nil
}

// lastUsedCoarsening is how stale last_used_at may be before ValidateAPIToken
// bumps it. Coarsening the write kills the per-request write amplification (one
// UPDATE on every authenticated API call) while keeping "last used" accurate to
// the minute — plenty for the UI's day-granularity display.
const lastUsedCoarsening = time.Minute

// ValidateAPIToken returns the owning tenant for a raw token and refreshes
// last_used_at at most once per lastUsedCoarsening window (not on every call).
// The bump is a conditional UPDATE in a CTE; the tenant is resolved by joining
// the token row directly (not the UPDATE's RETURNING), so authentication
// succeeds whether or not the bump fired this call.
func ValidateAPIToken(ctx context.Context, db *sql.DB, rawToken string) (*Tenant, error) {
	row := db.QueryRowContext(ctx, `
		WITH bumped AS (
			UPDATE devradar_api_token SET last_used_at = NOW()
			WHERE token_hash = $1
			  AND (last_used_at IS NULL OR last_used_at < NOW() - $2::interval)
		)
		SELECT `+prefixed("t")+`
		FROM devradar_api_token a JOIN devradar_tenant t ON t.id = a.tenant_id
		WHERE a.token_hash = $1`,
		HashToken(rawToken), fmt.Sprintf("%d seconds", int64(lastUsedCoarsening.Seconds())))
	t, err := scanTenant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTokenInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("validate api token: %w", err)
	}
	return t, nil
}

// CountAPITokens returns how many API tokens a tenant currently holds. Used to
// enforce a per-tenant issuance cap so a compromised session (or a bug) can't
// mint unbounded credentials.
func CountAPITokens(ctx context.Context, db *sql.DB, tenantID string) (int, error) {
	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM devradar_api_token WHERE tenant_id = $1`, tenantID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count api tokens: %w", err)
	}
	return n, nil
}

// ListAPITokens returns a tenant's tokens, newest first.
func ListAPITokens(ctx context.Context, db *sql.DB, tenantID string) ([]APITokenInfo, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, last_used_at, created_at FROM devradar_api_token
		 WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []APITokenInfo
	for rows.Next() {
		var ti APITokenInfo
		var last sql.NullTime
		if err := rows.Scan(&ti.ID, &ti.Name, &last, &ti.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan api token: %w", err)
		}
		if last.Valid {
			ti.LastUsed = &last.Time
		}
		out = append(out, ti)
	}
	return out, rows.Err()
}

// StashTokenFlash stores a freshly-minted raw token for one-time display,
// keyed to the tenant with a short TTL. It replaces any prior unread flash for
// the tenant (a new token supersedes an old unshown one). The raw token is
// never written anywhere else — this row is deleted the moment it is read
// (ConsumeTokenFlash). ttl bounds how long an unread flash may linger.
func StashTokenFlash(ctx context.Context, db *sql.DB, tenantID, rawToken string, ttl time.Duration) error {
	if _, err := db.ExecContext(ctx, `
		INSERT INTO devradar_token_flash (tenant_id, value, expires_at)
		VALUES ($1, $2, now() + $3::interval)
		ON CONFLICT (tenant_id) DO UPDATE
		SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at`,
		tenantID, rawToken, ttl.String()); err != nil {
		return fmt.Errorf("stash token flash: %w", err)
	}
	return nil
}

// ConsumeTokenFlash returns and deletes a tenant's one-time token flash, if any
// unexpired one exists (delete-and-return, so it is shown at most once). Returns
// an empty string with no error when there is nothing to show — the common case
// on an ordinary /tokens visit.
func ConsumeTokenFlash(ctx context.Context, db *sql.DB, tenantID string) (string, error) {
	var raw string
	err := db.QueryRowContext(ctx, `
		DELETE FROM devradar_token_flash
		WHERE tenant_id = $1 AND expires_at > now()
		RETURNING value`, tenantID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("consume token flash: %w", err)
	}
	return raw, nil
}

// RevokeAPIToken deletes a token owned by the tenant. Ownership is enforced in
// the WHERE clause so one tenant can never revoke another's token.
func RevokeAPIToken(ctx context.Context, db *sql.DB, tenantID, tokenID string) error {
	res, err := db.ExecContext(ctx,
		`DELETE FROM devradar_api_token WHERE id = $1 AND tenant_id = $2`, tokenID, tenantID)
	if err != nil {
		return fmt.Errorf("revoke api token: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("token not found or not owned by tenant")
	}
	return nil
}

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

// ErrTokenLimit is returned by CreateAPITokenWithLimit when minting a token would
// exceed the tenant's cap.
var ErrTokenLimit = errors.New("API token limit reached for tenant")

// APITokenInfo is a token's metadata (never the secret).
type APITokenInfo struct {
	ID        string
	Name      string
	LastUsed  *time.Time
	ExpiresAt *time.Time // nil ⇒ never expires
	CreatedAt time.Time
}

// CreateAPIToken generates a "dr_"-prefixed token, stores only its SHA-256 hash,
// and returns the raw token — shown to the user once, never persisted. A ttl > 0
// sets an expiry; ttl <= 0 mints a non-expiring token (the historical default).
func CreateAPIToken(ctx context.Context, db *sql.DB, tenantID, name string, ttl time.Duration) (string, error) {
	return CreateAPITokenWithLimit(ctx, db, tenantID, name, ttl, 0)
}

// CreateAPITokenWithLimit is CreateAPIToken with a per-tenant token cap
// (maxTokens <= 0 disables it). Inserts zero rows and returns ErrTokenLimit when
// at/over the cap. Matches the caps counted by CountAPITokens (all rows for the
// tenant).
//
// The cap is EXACT, not soft: unlike the SBOM/repository workload quotas (which
// protect cost and tolerate a bounded overshoot), the token cap is a SECURITY
// control — it bounds how many credentials a compromised session can mint. A
// single-statement "INSERT ... WHERE count < cap" does NOT serialize under READ
// COMMITTED, so concurrent mints could each see count < cap and both insert,
// deliberately blowing past the limit. We therefore serialize the count+insert
// per tenant with pg_advisory_xact_lock(hashtext(tenant_id)) inside a transaction.
// Token creation is rare (a human action), so the lock's contention cost is
// negligible; other tenants are unaffected (the lock key is the tenant).
func CreateAPITokenWithLimit(ctx context.Context, db *sql.DB, tenantID, name string, ttl time.Duration, maxTokens int) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate api token: %w", err)
	}
	rawToken := tokenPrefix + hex.EncodeToString(raw)
	var expires any // NULL ⇒ never expires
	if ttl > 0 {
		expires = time.Now().Add(ttl).UTC()
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin token tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Serialize admission for THIS tenant so the count+insert is atomic under
	// concurrency. Released at commit/rollback.
	if _, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtext($1))`, tenantID); err != nil {
		return "", fmt.Errorf("acquire token admission lock: %w", err)
	}

	res, err := tx.ExecContext(ctx, `
		INSERT INTO devradar_api_token (tenant_id, name, token_hash, expires_at)
		SELECT $1, $2, $3, $4
		WHERE $5 <= 0
		   OR (SELECT count(*) FROM devradar_api_token WHERE tenant_id = $1) < $5`,
		tenantID, name, HashToken(rawToken), expires, maxTokens)
	if err != nil {
		return "", fmt.Errorf("create api token: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrTokenLimit
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit token: %w", err)
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
	// An expired token authenticates no one: both the last_used bump and the
	// tenant lookup exclude rows whose expires_at has passed (NULL = never expires).
	row := db.QueryRowContext(ctx, `
		WITH bumped AS (
			UPDATE devradar_api_token SET last_used_at = NOW()
			WHERE token_hash = $1
			  AND (expires_at IS NULL OR expires_at > NOW())
			  AND (last_used_at IS NULL OR last_used_at < NOW() - $2::interval)
		)
		SELECT `+prefixed("t")+`
		FROM devradar_api_token a JOIN devradar_tenant t ON t.id = a.tenant_id
		WHERE a.token_hash = $1
		  AND (a.expires_at IS NULL OR a.expires_at > NOW())`,
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
		`SELECT id, name, last_used_at, expires_at, created_at FROM devradar_api_token
		 WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []APITokenInfo
	for rows.Next() {
		var ti APITokenInfo
		var last, expires sql.NullTime
		if err := rows.Scan(&ti.ID, &ti.Name, &last, &expires, &ti.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan api token: %w", err)
		}
		if last.Valid {
			ti.LastUsed = &last.Time
		}
		if expires.Valid {
			ti.ExpiresAt = &expires.Time
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
// The key encrypts the value at rest (AES-256-GCM) when non-nil; a nil key
// stores plaintext (local dev). See flashcrypt.go.
func StashTokenFlash(ctx context.Context, db *sql.DB, tenantID, rawToken string, ttl time.Duration, key []byte) error {
	stored, err := encryptFlash(key, rawToken)
	if err != nil {
		return fmt.Errorf("stash token flash: %w", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO devradar_token_flash (tenant_id, value, expires_at)
		VALUES ($1, $2, now() + $3::interval)
		ON CONFLICT (tenant_id) DO UPDATE
		SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at`,
		tenantID, stored, ttl.String()); err != nil {
		return fmt.Errorf("stash token flash: %w", err)
	}
	return nil
}

// ConsumeTokenFlash returns and deletes a tenant's one-time token flash, if any
// unexpired one exists (delete-and-return, so it is shown at most once). Returns
// an empty string with no error when there is nothing to show — the common case
// on an ordinary /tokens visit.
func ConsumeTokenFlash(ctx context.Context, db *sql.DB, tenantID string, key []byte) (string, error) {
	var stored string
	err := db.QueryRowContext(ctx, `
		DELETE FROM devradar_token_flash
		WHERE tenant_id = $1 AND expires_at > now()
		RETURNING value`, tenantID).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("consume token flash: %w", err)
	}
	return decryptFlash(key, stored)
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

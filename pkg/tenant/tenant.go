// Package tenant models DevRadar's identity: a tenant (a GitHub user/org), the
// browser sessions that authenticate the UI, and the API tokens CI uses to
// submit SBOMs. Tenant isolation is enforced in the query layer (WHERE
// tenant_id = $1); there is no RLS. Shapes mirror the devtrace_* tables.
package tenant

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Status values for a tenant account.
const (
	StatusActive    = "active"
	StatusSuspended = "suspended"
)

// Tenant is a row in devradar_tenant.
type Tenant struct {
	ID            string
	GitHubID      int64
	Username      string
	Email         string
	AvatarURL     string
	Plan          string
	Status        string
	TOSAcceptedAt *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanTenant(s scanner) (*Tenant, error) {
	var t Tenant
	var tos sql.NullTime
	err := s.Scan(&t.ID, &t.GitHubID, &t.Username, &t.Email, &t.AvatarURL,
		&t.Plan, &t.Status, &tos, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if tos.Valid {
		t.TOSAcceptedAt = &tos.Time
	}
	return &t, nil
}

const tenantColumns = `id, github_id, username, COALESCE(email,''), COALESCE(avatar_url,''),
	plan, status, tos_accepted_at, created_at, updated_at`

// UpsertTenant creates or updates a tenant from a GitHub identity (called on
// OAuth login), keyed on github_id. Returns the current row.
func UpsertTenant(ctx context.Context, db *sql.DB, githubID int64, username, email, avatarURL string) (*Tenant, error) {
	row := db.QueryRowContext(ctx, `
		INSERT INTO devradar_tenant (github_id, username, email, avatar_url)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (github_id) DO UPDATE SET
			username = EXCLUDED.username,
			email = COALESCE(NULLIF(EXCLUDED.email,''), devradar_tenant.email),
			avatar_url = EXCLUDED.avatar_url,
			updated_at = now()
		RETURNING `+tenantColumns,
		githubID, username, nullStr(email), nullStr(avatarURL))
	t, err := scanTenant(row)
	if err != nil {
		return nil, fmt.Errorf("upsert tenant: %w", err)
	}
	return t, nil
}

// GetTenant returns a tenant by id.
func GetTenant(ctx context.Context, db *sql.DB, id string) (*Tenant, error) {
	row := db.QueryRowContext(ctx, `SELECT `+tenantColumns+` FROM devradar_tenant WHERE id = $1`, id)
	t, err := scanTenant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get tenant: %w", err)
	}
	return t, nil
}

// ErrNotFound is returned when a tenant does not exist.
var ErrNotFound = errors.New("tenant not found")

// HashToken returns the hex SHA-256 of a raw token. Used for both sessions and
// API tokens — only the hash is ever stored.
func HashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

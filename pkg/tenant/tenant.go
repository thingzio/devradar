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

// Tenant is a row in devradar_tenant. Identity is the verified email address.
type Tenant struct {
	ID              string
	Email           string
	EmailVerifiedAt *time.Time
	Plan            string
	Status          string
	MinSeverity     string // minimum severity of interest for the read API/alerts
	AvatarURL       string // optional OAuth profile avatar (GitHub); "" for email-only
	TOSAcceptedAt   *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanTenant(s scanner) (*Tenant, error) {
	var t Tenant
	var verified, tos sql.NullTime
	var avatar sql.NullString
	err := s.Scan(&t.ID, &t.Email, &verified, &t.Plan, &t.Status, &t.MinSeverity,
		&avatar, &tos, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if verified.Valid {
		t.EmailVerifiedAt = &verified.Time
	}
	t.AvatarURL = avatar.String
	if tos.Valid {
		t.TOSAcceptedAt = &tos.Time
	}
	return &t, nil
}

const tenantColumns = `id, email, email_verified_at, plan, status, min_severity,
	avatar_url, tos_accepted_at, created_at, updated_at`

// UpsertTenantByEmail creates the tenant for email if absent (else returns the
// existing one) and marks the email verified — called when a magic-link is
// successfully consumed, which is proof the address is controlled. Email is
// normalized (trimmed, lowercased) by the caller.
func UpsertTenantByEmail(ctx context.Context, db *sql.DB, email string) (*Tenant, error) {
	row := db.QueryRowContext(ctx, `
		INSERT INTO devradar_tenant (email, email_verified_at)
		VALUES ($1, now())
		ON CONFLICT (email) DO UPDATE SET
			email_verified_at = COALESCE(devradar_tenant.email_verified_at, now()),
			updated_at = now()
		RETURNING `+tenantColumns, email)
	t, err := scanTenant(row)
	if err != nil {
		return nil, fmt.Errorf("upsert tenant by email: %w", err)
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

// SetMinSeverity updates a tenant's minimum severity of interest. The caller
// validates minSeverity (data.ValidMinSeverity) before calling.
func SetMinSeverity(ctx context.Context, db *sql.DB, tenantID, minSeverity string) error {
	if _, err := db.ExecContext(ctx,
		`UPDATE devradar_tenant SET min_severity = $2, updated_at = now() WHERE id = $1`,
		tenantID, minSeverity); err != nil {
		return fmt.Errorf("set min_severity: %w", err)
	}
	return nil
}

// ErrNotFound is returned when a tenant does not exist.
var ErrNotFound = errors.New("tenant not found")

// HashToken returns the hex SHA-256 of a raw token. Used for sessions, API
// tokens, and login tokens — only the hash is ever stored.
func HashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

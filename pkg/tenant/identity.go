package tenant

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Provider identifiers for devradar_identity.provider. Magic-link is modeled as
// an identity too (subject = email) so the table is a complete record of every
// way a tenant can authenticate.
const (
	ProviderMagicLink = "magiclink"
	ProviderGitHub    = "github"
)

// ResolveByIdentity maps an external sign-in to a compatibility tenant,
// provider-agnostically. It was the single spine for legacy magic-link and
// OAuth flows:
//
//  1. If (provider, subject) is already linked, return that tenant. Keying on the
//     provider's immutable subject means a later email change at the provider
//     never silently re-points the identity to a different tenant.
//  2. Otherwise resolve the tenant by verified email (upsert — sign-up and
//     sign-in are one flow), link this identity to it, and return it.
//
// email MUST already be proven (a consumed magic link, or a provider-verified
// address); callers never pass an unverified address. There is no account-linking
// UI: if a provider reports a verified email that differs from an existing
// tenant's, step 2 creates a distinct tenant — the email is the join key.
//
// avatarURL is an optional cosmetic profile image from the provider; pass "" for
// providers that have none (magic-link). When non-empty it is refreshed on the
// tenant on every sign-in, since the provider avatar can change.
//
// Transitional: compatibility API until Task 4 moves the remaining
// tenant-auth callers to postgres.Store.ResolveDirectIdentity.
func ResolveByIdentity(ctx context.Context, db *sql.DB, provider, subject, email, avatarURL string) (*Tenant, error) {
	email = NormalizeEmail(email)

	// Fast path: identity already linked.
	t, err := getTenantByIdentity(ctx, db, provider, subject)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if errors.Is(err, ErrNotFound) {
		// First sign-in with this identity: resolve/create the tenant by email, then
		// link. UpsertTenantByEmail is idempotent, and the identity insert is guarded
		// by ON CONFLICT so a concurrent first sign-in cannot create a duplicate link.
		t, err = UpsertTenantByEmail(ctx, db, email)
		if err != nil {
			return nil, err
		}
		if _, err := db.ExecContext(ctx, `
			INSERT INTO devradar_identity (tenant_id, provider, subject, email)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (provider, subject) DO NOTHING`,
			t.ID, provider, subject, email); err != nil {
			return nil, fmt.Errorf("link identity: %w", err)
		}
	}

	// Refresh the avatar if the provider supplied one and it changed.
	if avatarURL != "" && avatarURL != t.AvatarURL {
		if _, err := db.ExecContext(ctx,
			`UPDATE devradar_tenant SET avatar_url = $2, updated_at = now() WHERE id = $1`,
			t.ID, avatarURL); err != nil {
			return nil, fmt.Errorf("update avatar: %w", err)
		}
		t.AvatarURL = avatarURL
	}
	return t, nil
}

// getTenantByIdentity returns the tenant linked to (provider, subject), or
// ErrNotFound if the identity is not yet linked.
func getTenantByIdentity(ctx context.Context, db *sql.DB, provider, subject string) (*Tenant, error) {
	row := db.QueryRowContext(ctx, `
		SELECT `+prefixed("t")+`
		FROM devradar_identity i JOIN devradar_tenant t ON t.id = i.tenant_id
		WHERE i.provider = $1 AND i.subject = $2`, provider, subject)
	t, err := scanTenant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get tenant by identity: %w", err)
	}
	return t, nil
}

package tenant

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
)

// Plans is the allowlist of valid tenant plans. DevRadar has no billing package;
// plan is a free-text column, so the admin console validates against this set.
var Plans = []string{"free", "paid"}

// ValidPlan reports whether p is a known plan.
func ValidPlan(p string) bool { return slices.Contains(Plans, p) }

// AdminListTenants returns a page of tenants ordered by newest first, plus the
// total matching count. A non-empty query does a case-insensitive substring
// match on email. This is an operator-console read: it is deliberately NOT
// tenant-scoped (it spans all tenants), which is the whole point of the console.
func AdminListTenants(ctx context.Context, db *sql.DB, query string, limit, offset int) ([]*Tenant, int, error) {
	where, args := "", []any{}
	if query != "" {
		where = `WHERE email ILIKE $1`
		args = append(args, "%"+query+"%")
	}

	var total int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_tenant `+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count tenants: %w", err)
	}

	args = append(args, limit, offset)
	rows, err := db.QueryContext(ctx,
		`SELECT `+tenantColumns+` FROM devradar_tenant `+where+
			fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []*Tenant
	for rows.Next() {
		t, err := scanTenant(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan tenant: %w", err)
		}
		out = append(out, t)
	}
	return out, total, rows.Err()
}

// SetPlan updates a tenant's plan. The caller validates plan (ValidPlan).
func SetPlan(ctx context.Context, db *sql.DB, tenantID, plan string) error {
	if _, err := db.ExecContext(ctx,
		`UPDATE devradar_tenant SET plan = $2, updated_at = now() WHERE id = $1`,
		tenantID, plan); err != nil {
		return fmt.Errorf("set plan: %w", err)
	}
	return nil
}

// SetStatus updates a tenant's account status (active|suspended). The caller
// validates status.
func SetStatus(ctx context.Context, db *sql.DB, tenantID, status string) error {
	if _, err := db.ExecContext(ctx,
		`UPDATE devradar_tenant SET status = $2, updated_at = now() WHERE id = $1`,
		tenantID, status); err != nil {
		return fmt.Errorf("set status: %w", err)
	}
	return nil
}

// DeleteTenant hard-deletes a tenant. Child rows (sessions, tokens, sboms,
// findings, …) cascade via ON DELETE CASCADE.
func DeleteTenant(ctx context.Context, db *sql.DB, tenantID string) error {
	res, err := db.ExecContext(ctx, `DELETE FROM devradar_tenant WHERE id = $1`, tenantID)
	if err != nil {
		return fmt.Errorf("delete tenant: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AdminRevokeAPIToken deletes an API token by id without a tenant predicate —
// an operator action. Returns ErrNotFound if no such token exists.
func AdminRevokeAPIToken(ctx context.Context, db *sql.DB, tokenID string) error {
	res, err := db.ExecContext(ctx, `DELETE FROM devradar_api_token WHERE id = $1`, tokenID)
	if err != nil {
		return fmt.Errorf("admin revoke api token: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/thingzio/devradar/pkg/account"
)

const accountColumns = `id,name,plan,status,min_severity,created_at,updated_at`

const userColumns = `id,email,email_verified_at,status,avatar_url,tos_accepted_at,created_at,updated_at`

var (
	errCompatibilityOwnerAmbiguous = errors.New("compatibility account has ambiguous identity owners")
	errCompatibilityOwnerMissing   = errors.New("modern compatibility account has no identity owner")
)

type compatibilityOwner struct {
	userID string
	legacy bool
}

// GetAccount returns the account identified by accountID, regardless of status.
func (s *Store) GetAccount(ctx context.Context, accountID string) (*account.Account, error) {
	var a account.Account
	err := scanAccount(s.db.QueryRowContext(ctx, `
		SELECT `+accountColumns+` FROM devradar_tenant WHERE id=$1`, accountID), &a)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get account: %w", err)
	}
	return &a, nil
}

// GetUser returns the user identified by userID, regardless of status.
func (s *Store) GetUser(ctx context.Context, userID string) (*account.User, error) {
	var u account.User
	err := scanUser(s.db.QueryRowContext(ctx, `
		SELECT `+userColumns+` FROM devradar_user WHERE id=$1`, userID), &u)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	return &u, nil
}

// ListUserAccounts returns active access contexts in stable display order.
func (s *Store) ListUserAccounts(ctx context.Context, userID string) ([]account.Access, error) {
	rows, err := s.db.QueryContext(ctx, accessSelect+`
		WHERE u.id=$1 AND u.status='active' AND t.status='active'
		  AND m.revoked_at IS NULL
		ORDER BY lower(t.name),t.id`, userID)
	if err != nil {
		return nil, fmt.Errorf("list user accounts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var accesses []account.Access
	for rows.Next() {
		var access account.Access
		if err := scanAccess(rows, &access); err != nil {
			return nil, fmt.Errorf("list user accounts: %w", err)
		}
		accesses = append(accesses, access)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list user accounts: %w", err)
	}
	return accesses, nil
}

// GetAccess returns an active user's unrevoked access to an active account.
func (s *Store) GetAccess(ctx context.Context, userID, accountID string) (*account.Access, error) {
	var access account.Access
	err := scanAccess(s.db.QueryRowContext(ctx, accessSelect+`
		WHERE u.id=$1 AND t.id=$2 AND u.status='active' AND t.status='active'
		  AND m.revoked_at IS NULL`, userID, accountID), &access)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get access: %w", err)
	}
	return &access, nil
}

// ReconcileLegacyAccount upgrades one account written by an old application
// revision after migration 030's initial backfill. Reconciliation is expand-only:
// existing credential ownership and membership state are authoritative. Only
// NULL identity/session user IDs written by an old revision are backfilled, and
// only live legacy sessions receive an active account.
func (s *Store) ReconcileLegacyAccount(ctx context.Context, accountID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin legacy account reconciliation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var exists string
	if err := tx.QueryRowContext(ctx,
		`SELECT id FROM devradar_tenant WHERE id=$1 FOR UPDATE`, accountID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("lock legacy account: %w", err)
	}
	if err := reconcileCompatibilityAccount(ctx, tx, accountID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit legacy account reconciliation: %w", err)
	}
	return nil
}

func reconcileCompatibilityAccount(
	ctx context.Context,
	tx *sql.Tx,
	accountID string,
) error {
	owner, found, err := resolveCompatibilityOwner(ctx, tx, accountID)
	if err != nil {
		return err
	}
	if !found {
		user, err := ensureLegacyUser(ctx, tx, accountID)
		if err != nil {
			return err
		}
		owner = compatibilityOwner{userID: user.ID, legacy: true}
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE devradar_tenant SET name=left(btrim(email),80)
		WHERE id=$1 AND name=''`, accountID); err != nil {
		return fmt.Errorf("backfill compatibility account name: %w", err)
	}
	if owner.legacy {
		if err := insertLegacyAdminMembership(ctx, tx, accountID, owner.userID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE devradar_identity SET user_id=$2
		WHERE tenant_id=$1 AND user_id IS NULL`, accountID, owner.userID); err != nil {
		return fmt.Errorf("backfill compatibility identities: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE devradar_session s
		SET user_id=$2,
		    active_account_id=CASE WHEN EXISTS (
			SELECT 1 FROM devradar_account_member m
			JOIN devradar_tenant t ON t.id=m.account_id
			WHERE m.account_id=$1 AND m.user_id=$2
			  AND m.revoked_at IS NULL AND t.status='active'
		    ) THEN $1::uuid ELSE NULL END
		WHERE s.tenant_id=$1 AND s.user_id IS NULL AND s.expires_at>now()`,
		accountID, owner.userID); err != nil {
		return fmt.Errorf("backfill compatibility sessions: %w", err)
	}
	return nil
}

func resolveCompatibilityOwner(
	ctx context.Context,
	tx *sql.Tx,
	accountID string,
) (compatibilityOwner, bool, error) {
	var legacyUserID string
	err := tx.QueryRowContext(ctx,
		`SELECT id FROM devradar_user WHERE legacy_tenant_id=$1`, accountID).Scan(&legacyUserID)
	if err == nil {
		return compatibilityOwner{userID: legacyUserID, legacy: true}, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return compatibilityOwner{}, false, fmt.Errorf("read legacy compatibility owner: %w", err)
	}

	var ownerCount int
	var identityUserID sql.NullString
	if err := tx.QueryRowContext(ctx, `
		SELECT count(DISTINCT user_id),min(user_id::text)
		FROM devradar_identity
		WHERE tenant_id=$1 AND user_id IS NOT NULL`, accountID).
		Scan(&ownerCount, &identityUserID); err != nil {
		return compatibilityOwner{}, false, fmt.Errorf("read modern compatibility owner: %w", err)
	}
	switch ownerCount {
	case 1:
		return compatibilityOwner{userID: identityUserID.String}, true, nil
	case 0:
		var hasModernState bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM devradar_account_member WHERE account_id=$1
				UNION ALL
				SELECT 1 FROM devradar_session WHERE tenant_id=$1 AND user_id IS NOT NULL
			)`, accountID).Scan(&hasModernState); err != nil {
			return compatibilityOwner{}, false, fmt.Errorf("check modern compatibility state: %w", err)
		}
		if hasModernState {
			return compatibilityOwner{}, false, errCompatibilityOwnerMissing
		}
		return compatibilityOwner{}, false, nil
	default:
		return compatibilityOwner{}, false, errCompatibilityOwnerAmbiguous
	}
}

// ReconcileLegacyAccounts upgrades every account with incomplete legacy
// compatibility state. IDs are deduplicated and processed in stable order to
// keep concurrent lock order deterministic.
func (s *Store) ReconcileLegacyAccounts(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT t.id
		FROM devradar_tenant t
		LEFT JOIN devradar_user u ON u.legacy_tenant_id=t.id
		WHERE u.id IS NULL
		   OR t.name=''
		   OR (u.id IS NOT NULL AND NOT EXISTS (
			SELECT 1 FROM devradar_account_member m
			WHERE m.account_id=t.id AND m.user_id=u.id
		   ))
		   OR EXISTS (
			SELECT 1 FROM devradar_identity i
			WHERE i.tenant_id=t.id AND i.user_id IS NULL
		   )
		   OR EXISTS (
			SELECT 1 FROM devradar_session s
			WHERE s.tenant_id=t.id AND s.expires_at>now()
			  AND s.user_id IS NULL
		   )
		ORDER BY t.id`)
	if err != nil {
		return fmt.Errorf("list legacy accounts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var accountIDs []string
	for rows.Next() {
		var accountID string
		if err := rows.Scan(&accountID); err != nil {
			return fmt.Errorf("scan legacy account: %w", err)
		}
		accountIDs = append(accountIDs, accountID)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate legacy accounts: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close legacy accounts: %w", err)
	}

	for _, accountID := range accountIDs {
		if err := s.ReconcileLegacyAccount(ctx, accountID); err != nil {
			return fmt.Errorf("reconcile legacy account %s: %w", accountID, err)
		}
	}
	return nil
}

const accessSelect = `
	SELECT
		u.id,u.email,u.email_verified_at,u.status,u.avatar_url,u.tos_accepted_at,
		u.created_at,u.updated_at,
		t.id,t.name,t.plan,t.status,t.min_severity,t.created_at,t.updated_at,
		m.account_id,m.user_id,m.role,m.created_by_user_id,m.accepted_at,
		m.revoked_at,m.revoked_by_user_id,m.created_at,m.updated_at
	FROM devradar_account_member m
	JOIN devradar_user u ON u.id=m.user_id
	JOIN devradar_tenant t ON t.id=m.account_id`

type accountScanner interface {
	Scan(dest ...any) error
}

func scanAccount(row accountScanner, a *account.Account) error {
	return row.Scan(&a.ID, &a.Name, &a.Plan, &a.Status, &a.MinSeverity,
		&a.CreatedAt, &a.UpdatedAt)
}

func scanUser(row accountScanner, u *account.User) error {
	var verifiedAt, tosAcceptedAt sql.NullTime
	var avatarURL sql.NullString
	if err := row.Scan(&u.ID, &u.Email, &verifiedAt, &u.Status, &avatarURL,
		&tosAcceptedAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return err
	}
	u.AvatarURL = avatarURL.String
	if verifiedAt.Valid {
		u.EmailVerifiedAt = &verifiedAt.Time
	}
	if tosAcceptedAt.Valid {
		u.TOSAcceptedAt = &tosAcceptedAt.Time
	}
	return nil
}

func scanAccess(row accountScanner, access *account.Access) error {
	var verifiedAt, tosAcceptedAt, revokedAt sql.NullTime
	var avatarURL, createdByUserID, revokedByUserID sql.NullString
	if err := row.Scan(
		&access.Actor.ID, &access.Actor.Email, &verifiedAt, &access.Actor.Status,
		&avatarURL, &tosAcceptedAt, &access.Actor.CreatedAt, &access.Actor.UpdatedAt,
		&access.Account.ID, &access.Account.Name, &access.Account.Plan,
		&access.Account.Status, &access.Account.MinSeverity, &access.Account.CreatedAt,
		&access.Account.UpdatedAt, &access.Membership.AccountID,
		&access.Membership.UserID, &access.Membership.Role, &createdByUserID,
		&access.Membership.AcceptedAt, &revokedAt, &revokedByUserID,
		&access.Membership.CreatedAt, &access.Membership.UpdatedAt,
	); err != nil {
		return err
	}
	access.Actor.AvatarURL = avatarURL.String
	if verifiedAt.Valid {
		access.Actor.EmailVerifiedAt = &verifiedAt.Time
	}
	if tosAcceptedAt.Valid {
		access.Actor.TOSAcceptedAt = &tosAcceptedAt.Time
	}
	if createdByUserID.Valid {
		access.Membership.CreatedByUserID = &createdByUserID.String
	}
	if revokedAt.Valid {
		access.Membership.RevokedAt = &revokedAt.Time
	}
	if revokedByUserID.Valid {
		access.Membership.RevokedByUserID = &revokedByUserID.String
	}
	return nil
}

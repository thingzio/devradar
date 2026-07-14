package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/authn"
)

var (
	// ErrLoginTokenInvalid identifies an unknown or already consumed login token.
	ErrLoginTokenInvalid = errors.New("login link invalid or already used")
	// ErrLoginTokenExpired identifies a login token whose TTL elapsed.
	ErrLoginTokenExpired = errors.New("login link expired")
	// ErrSessionInvalid identifies an unknown or expired browser session.
	ErrSessionInvalid = errors.New("session expired or not found")
	// ErrAPITokenInvalid identifies an unknown, revoked, or expired API token.
	ErrAPITokenInvalid = errors.New("invalid or revoked API token")
)

var errIdentityLinkRace = errors.New("identity linked concurrently")

const apiTokenLastUsedCoarsening = time.Minute

// ValidateAPIToken resolves a raw account credential without loading a human
// user or membership. last_used_at is refreshed at most once per minute.
func (s *Store) ValidateAPIToken(
	ctx context.Context,
	raw string,
) (*account.Account, account.Actor, error) {
	var acct account.Account
	var tokenID string
	err := s.db.QueryRowContext(ctx, `
		WITH bumped AS (
			UPDATE devradar_api_token SET last_used_at=now()
			WHERE token_hash=$1
			  AND (expires_at IS NULL OR expires_at>now())
			  AND (last_used_at IS NULL OR last_used_at<now()-$2::interval)
		)
		SELECT t.id,t.name,t.plan,t.status,t.min_severity,t.created_at,t.updated_at,a.id
		FROM devradar_api_token a
		JOIN devradar_tenant t ON t.id=a.tenant_id
		WHERE a.token_hash=$1
		  AND (a.expires_at IS NULL OR a.expires_at>now())`,
		authn.HashToken(raw), apiTokenLastUsedCoarsening.String()).
		Scan(&acct.ID, &acct.Name, &acct.Plan, &acct.Status, &acct.MinSeverity,
			&acct.CreatedAt, &acct.UpdatedAt, &tokenID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, account.Actor{}, ErrAPITokenInvalid
	}
	if err != nil {
		return nil, account.Actor{}, fmt.Errorf("validate api token: %w", err)
	}
	return &acct, account.Actor{Kind: account.ActorAPIToken, APITokenID: tokenID}, nil
}

// ResolveDirectIdentity resolves a verified identity to its authoritative user.
// Only a user created by this direct-signup transaction receives a new account.
func (s *Store) ResolveDirectIdentity(
	ctx context.Context,
	identity account.VerifiedIdentity,
) (*account.User, *account.Account, error) {
	identity.Email = authn.NormalizeEmail(identity.Email)
	for attempt := 0; attempt < 2; attempt++ {
		user, acct, err := s.resolveDirectIdentity(ctx, identity)
		if errors.Is(err, errIdentityLinkRace) {
			continue
		}
		return user, acct, err
	}
	return nil, nil, fmt.Errorf("resolve direct identity: %w", errIdentityLinkRace)
}

func (s *Store) resolveDirectIdentity(
	ctx context.Context,
	identity account.VerifiedIdentity,
) (*account.User, *account.Account, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("begin identity resolution: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	user, compatibilityAccountID, found, err := identityOwner(ctx, tx, identity.Provider, identity.Subject)
	if err != nil {
		return nil, nil, err
	}
	if found && user == nil {
		if compatibilityAccountID == nil {
			return nil, nil, errors.New("resolve direct identity: identity has no owner")
		}
		user, err = reconcileLegacyIdentityOwner(ctx, tx, identity.Provider, identity.Subject,
			*compatibilityAccountID)
		if err != nil {
			return nil, nil, err
		}
	}

	var createdAccountID *string
	if !found {
		if _, err := tx.ExecContext(ctx,
			`SELECT pg_advisory_xact_lock(hashtext($1))`, identity.Email); err != nil {
			return nil, nil, fmt.Errorf("lock verified email: %w", err)
		}
		user, compatibilityAccountID, found, err = identityOwner(
			ctx, tx, identity.Provider, identity.Subject)
		if err != nil {
			return nil, nil, err
		}
		if found && user == nil {
			if compatibilityAccountID == nil {
				return nil, nil, errors.New("resolve direct identity: identity has no owner")
			}
			user, err = reconcileLegacyIdentityOwner(ctx, tx, identity.Provider, identity.Subject,
				*compatibilityAccountID)
			if err != nil {
				return nil, nil, err
			}
		}
		if !found {
			user, err = userByEmail(ctx, tx, identity.Email)
			switch {
			case err == nil:
			case errors.Is(err, ErrNotFound):
				user, createdAccountID, err = createDirectUserAccount(ctx, tx, identity)
				if err != nil {
					return nil, nil, err
				}
			default:
				return nil, nil, err
			}

			result, err := tx.ExecContext(ctx, `
				INSERT INTO devradar_identity
					(tenant_id,user_id,provider,subject,email)
				VALUES ($1,$2,$3,$4,$5)
				ON CONFLICT (provider,subject) DO NOTHING`,
				createdAccountID, user.ID, identity.Provider, identity.Subject, identity.Email)
			if err != nil {
				return nil, nil, fmt.Errorf("link verified identity: %w", err)
			}
			linked, err := result.RowsAffected()
			if err != nil {
				return nil, nil, fmt.Errorf("read identity link result: %w", err)
			}
			if linked != 1 {
				return nil, nil, errIdentityLinkRace
			}
		}
	}

	if err := scanUser(tx.QueryRowContext(ctx, `
		UPDATE devradar_user
		SET avatar_url=CASE WHEN $2='' THEN avatar_url ELSE $2 END,
		    email_verified_at=COALESCE(email_verified_at,now()),updated_at=now()
		WHERE id=$1
		RETURNING `+userColumns, user.ID, identity.AvatarURL), user); err != nil {
		return nil, nil, fmt.Errorf("verify identity user: %w", err)
	}

	acct, err := onlyActiveAccount(ctx, tx, user.ID)
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("commit identity resolution: %w", err)
	}
	return user, acct, nil
}

func identityOwner(
	ctx context.Context,
	tx *sql.Tx,
	provider, subject string,
) (*account.User, *string, bool, error) {
	var userID, accountID sql.NullString
	err := tx.QueryRowContext(ctx, `
		SELECT user_id,tenant_id FROM devradar_identity
		WHERE provider=$1 AND subject=$2`, provider, subject).Scan(&userID, &accountID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, fmt.Errorf("find verified identity: %w", err)
	}
	var compatibilityAccountID *string
	if accountID.Valid {
		compatibilityAccountID = &accountID.String
	}
	if !userID.Valid {
		return nil, compatibilityAccountID, true, nil
	}
	user, err := userByID(ctx, tx, userID.String)
	if err != nil {
		return nil, nil, false, err
	}
	return user, compatibilityAccountID, true, nil
}

func reconcileLegacyIdentityOwner(
	ctx context.Context,
	tx *sql.Tx,
	provider, subject, accountID string,
) (*account.User, error) {
	if _, err := tx.ExecContext(ctx,
		`SELECT id FROM devradar_tenant WHERE id=$1 FOR UPDATE`, accountID); err != nil {
		return nil, fmt.Errorf("lock legacy identity account: %w", err)
	}
	user, err := ensureLegacyUser(ctx, tx, accountID)
	if err != nil {
		return nil, err
	}
	if err := insertLegacyAdminMembership(ctx, tx, accountID, user.ID); err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE devradar_identity SET user_id=$3
		WHERE provider=$1 AND subject=$2 AND user_id IS NULL`, provider, subject, user.ID)
	if err != nil {
		return nil, fmt.Errorf("backfill legacy identity owner: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("read legacy identity backfill result: %w", err)
	}
	if updated == 0 {
		owner, _, found, err := identityOwner(ctx, tx, provider, subject)
		if err != nil {
			return nil, err
		}
		if !found || owner == nil {
			return nil, errors.New("legacy identity owner disappeared")
		}
		return owner, nil
	}
	return user, nil
}

func createDirectUserAccount(
	ctx context.Context,
	tx *sql.Tx,
	identity account.VerifiedIdentity,
) (*account.User, *string, error) {
	var legacyAccountID string
	err := tx.QueryRowContext(ctx,
		`SELECT id FROM devradar_tenant WHERE email=$1 FOR UPDATE`, identity.Email).
		Scan(&legacyAccountID)
	if err == nil {
		user, err := ensureLegacyUser(ctx, tx, legacyAccountID)
		if err != nil {
			return nil, nil, err
		}
		if err := insertLegacyAdminMembership(ctx, tx, legacyAccountID, user.ID); err != nil {
			return nil, nil, err
		}
		return user, &legacyAccountID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, nil, fmt.Errorf("find legacy signup account: %w", err)
	}

	var user account.User
	err = scanUser(tx.QueryRowContext(ctx, `
		INSERT INTO devradar_user (email,email_verified_at,status,avatar_url)
		VALUES ($1,now(),'active',NULLIF($2,''))
		RETURNING `+userColumns, identity.Email, identity.AvatarURL), &user)
	if err != nil {
		return nil, nil, fmt.Errorf("create direct user: %w", err)
	}
	name := firstRunes(identity.Email, 80)
	var accountID string
	err = tx.QueryRowContext(ctx, `
		INSERT INTO devradar_tenant (email,email_verified_at,name,avatar_url)
		VALUES ($1,now(),$2,NULLIF($3,'')) RETURNING id`,
		identity.Email, name, identity.AvatarURL).Scan(&accountID)
	if err != nil {
		return nil, nil, fmt.Errorf("create direct account: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO devradar_account_member
			(account_id,user_id,role,created_by_user_id,accepted_at)
		VALUES ($1,$2,'admin',$2,now())`, accountID, user.ID); err != nil {
		return nil, nil, fmt.Errorf("create direct admin membership: %w", err)
	}
	return &user, &accountID, nil
}

func firstRunes(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}

func onlyActiveAccount(ctx context.Context, tx *sql.Tx, userID string) (*account.Account, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT t.id,t.name,t.plan,t.status,t.min_severity,t.created_at,t.updated_at
		FROM devradar_account_member m
		JOIN devradar_tenant t ON t.id=m.account_id
		WHERE m.user_id=$1 AND m.revoked_at IS NULL AND t.status='active'
		ORDER BY t.id LIMIT 2`, userID)
	if err != nil {
		return nil, fmt.Errorf("list active identity accounts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var accounts []account.Account
	for rows.Next() {
		var acct account.Account
		if err := scanAccount(rows, &acct); err != nil {
			return nil, fmt.Errorf("scan active identity account: %w", err)
		}
		accounts = append(accounts, acct)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate active identity accounts: %w", err)
	}
	if len(accounts) != 1 {
		return nil, nil
	}
	return &accounts[0], nil
}

func userByEmail(ctx context.Context, tx *sql.Tx, email string) (*account.User, error) {
	var user account.User
	err := scanUser(tx.QueryRowContext(ctx, `
		SELECT `+userColumns+` FROM devradar_user WHERE email=$1`, email), &user)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return &user, nil
}

func userByID(ctx context.Context, tx *sql.Tx, userID string) (*account.User, error) {
	var user account.User
	err := scanUser(tx.QueryRowContext(ctx, `
		SELECT `+userColumns+` FROM devradar_user WHERE id=$1`, userID), &user)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get session user: %w", err)
	}
	return &user, nil
}

func ensureLegacyUser(ctx context.Context, tx *sql.Tx, accountID string) (*account.User, error) {
	var user account.User
	err := scanUser(tx.QueryRowContext(ctx, `
		SELECT `+userColumns+` FROM devradar_user WHERE legacy_tenant_id=$1`, accountID), &user)
	if err == nil {
		return &user, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("find legacy user: %w", err)
	}
	err = scanUser(tx.QueryRowContext(ctx, `
		INSERT INTO devradar_user
			(email,email_verified_at,status,avatar_url,tos_accepted_at,
			 legacy_tenant_id,created_at,updated_at)
		SELECT lower(btrim(email)),email_verified_at,'active',avatar_url,tos_accepted_at,
		       id,created_at,updated_at
		FROM devradar_tenant WHERE id=$1
		RETURNING `+userColumns, accountID), &user)
	if err != nil {
		return nil, fmt.Errorf("create legacy user: %w", err)
	}
	return &user, nil
}

func insertLegacyAdminMembership(ctx context.Context, tx *sql.Tx, accountID, userID string) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO devradar_account_member (account_id,user_id,role,accepted_at)
		SELECT t.id,$2,'admin',COALESCE(t.email_verified_at,t.created_at)
		FROM devradar_tenant t WHERE t.id=$1
		ON CONFLICT (account_id,user_id) DO NOTHING`, accountID, userID); err != nil {
		return fmt.Errorf("create legacy admin membership: %w", err)
	}
	return nil
}

// CreateLoginToken creates a single-use token and stores only its hash.
func (s *Store) CreateLoginToken(ctx context.Context, email string, ttl time.Duration) (string, error) {
	raw, err := authn.NewToken("")
	if err != nil {
		return "", err
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO devradar_login_token (id,email,expires_at)
		VALUES ($1,$2,now()+$3::interval)`,
		authn.HashToken(raw), authn.NormalizeEmail(email), ttl.String()); err != nil {
		return "", fmt.Errorf("create login token: %w", err)
	}
	return raw, nil
}

// PeekLoginToken validates a login token without consuming it.
func (s *Store) PeekLoginToken(ctx context.Context, raw string) (string, error) {
	var email string
	var expired bool
	err := s.db.QueryRowContext(ctx, `
		SELECT email,expires_at<=now() FROM devradar_login_token WHERE id=$1`,
		authn.HashToken(raw)).Scan(&email, &expired)
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

// ConsumeLoginToken atomically consumes a valid login token and returns its
// verified magic-link identity.
func (s *Store) ConsumeLoginToken(ctx context.Context, raw string) (account.VerifiedIdentity, error) {
	var email string
	err := s.db.QueryRowContext(ctx, `
		DELETE FROM devradar_login_token
		WHERE id=$1 AND expires_at>now()
		RETURNING email`, authn.HashToken(raw)).Scan(&email)
	if errors.Is(err, sql.ErrNoRows) {
		var expired bool
		if err := s.db.QueryRowContext(ctx, `
			SELECT expires_at<=now() FROM devradar_login_token WHERE id=$1`,
			authn.HashToken(raw)).Scan(&expired); err == nil && expired {
			return account.VerifiedIdentity{}, ErrLoginTokenExpired
		}
		return account.VerifiedIdentity{}, ErrLoginTokenInvalid
	}
	if err != nil {
		return account.VerifiedIdentity{}, fmt.Errorf("consume login token: %w", err)
	}
	return account.VerifiedIdentity{Provider: "magiclink", Subject: email, Email: email}, nil
}

// CreateSession authenticates userID with an optional active account. Selected
// accounts are dual-written to the compatibility tenant column.
func (s *Store) CreateSession(
	ctx context.Context,
	userID string,
	activeAccountID *string,
	ttl time.Duration,
) (string, error) {
	raw, err := authn.NewToken("")
	if err != nil {
		return "", err
	}
	var result sql.Result
	if activeAccountID == nil {
		result, err = s.db.ExecContext(ctx, `
			INSERT INTO devradar_session (id,tenant_id,user_id,active_account_id,expires_at)
			SELECT $1,NULL,u.id,NULL,now()+$3::interval
			FROM devradar_user u WHERE u.id=$2 AND u.status='active'`,
			authn.HashToken(raw), userID, ttl.String())
	} else {
		result, err = s.db.ExecContext(ctx, `
			INSERT INTO devradar_session (id,tenant_id,user_id,active_account_id,expires_at)
			SELECT $1,t.id,u.id,t.id,now()+$4::interval
			FROM devradar_user u
			JOIN devradar_account_member m ON m.user_id=u.id
			JOIN devradar_tenant t ON t.id=m.account_id
			WHERE u.id=$2 AND t.id=$3 AND u.status='active' AND t.status='active'
			  AND m.revoked_at IS NULL`,
			authn.HashToken(raw), userID, *activeAccountID, ttl.String())
	}
	if err != nil {
		return "", fmt.Errorf("create session: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("read create session result: %w", err)
	}
	if inserted != 1 {
		return "", ErrNotFound
	}
	return raw, nil
}

// ValidateSession returns a valid session's user and optional active account.
func (s *Store) ValidateSession(ctx context.Context, raw string) (*account.Session, error) {
	hash := authn.HashToken(raw)
	for attempt := 0; attempt < 2; attempt++ {
		var userID, tenantID, activeAccountID sql.NullString
		var expiresAt time.Time
		err := s.db.QueryRowContext(ctx, `
			SELECT user_id,tenant_id,active_account_id,expires_at
			FROM devradar_session WHERE id=$1 AND expires_at>now()`, hash).
			Scan(&userID, &tenantID, &activeAccountID, &expiresAt)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSessionInvalid
		}
		if err != nil {
			return nil, fmt.Errorf("validate session: %w", err)
		}
		if !userID.Valid {
			if attempt != 0 || !tenantID.Valid {
				return nil, ErrSessionInvalid
			}
			if err := s.repairLegacySession(ctx, hash, tenantID.String); err != nil {
				return nil, err
			}
			continue
		}
		user, err := s.GetUser(ctx, userID.String)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil, ErrSessionInvalid
			}
			return nil, err
		}
		session := &account.Session{User: *user, ExpiresAt: expiresAt}
		if activeAccountID.Valid {
			session.ActiveAccountID = &activeAccountID.String
		}
		return session, nil
	}
	return nil, ErrSessionInvalid
}

func (s *Store) repairLegacySession(ctx context.Context, hash, accountID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin legacy session repair: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`SELECT id FROM devradar_tenant WHERE id=$1 FOR UPDATE`, accountID); err != nil {
		return fmt.Errorf("lock legacy session account: %w", err)
	}
	var sessionUserID, sessionAccountID sql.NullString
	err = tx.QueryRowContext(ctx, `
		SELECT user_id,tenant_id FROM devradar_session
		WHERE id=$1 AND expires_at>now() FOR UPDATE`, hash).
		Scan(&sessionUserID, &sessionAccountID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrSessionInvalid
	}
	if err != nil {
		return fmt.Errorf("lock legacy session: %w", err)
	}
	if sessionUserID.Valid {
		return tx.Commit()
	}
	if !sessionAccountID.Valid || sessionAccountID.String != accountID {
		return ErrSessionInvalid
	}
	if err := reconcileCompatibilityAccount(ctx, tx, accountID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit legacy session repair: %w", err)
	}
	return nil
}

// SelectSessionAccount selects accountID only when the session user has an
// active membership, dual-writing the compatibility tenant column.
func (s *Store) SelectSessionAccount(ctx context.Context, raw, userID, accountID string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE devradar_session s
		SET tenant_id=$3,active_account_id=$3
		WHERE s.id=$1 AND s.user_id=$2 AND s.expires_at>now()
		  AND EXISTS (
			SELECT 1 FROM devradar_account_member m
			JOIN devradar_tenant t ON t.id=m.account_id
			JOIN devradar_user u ON u.id=m.user_id
			WHERE m.account_id=$3 AND m.user_id=$2 AND m.revoked_at IS NULL
			  AND t.status='active' AND u.status='active'
		  )`, authn.HashToken(raw), userID, accountID)
	if err != nil {
		return fmt.Errorf("select session account: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read session account selection result: %w", err)
	}
	if updated != 1 {
		return ErrNotFound
	}
	return nil
}

// DestroySession invalidates a browser session.
func (s *Store) DestroySession(ctx context.Context, raw string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM devradar_session WHERE id=$1`, authn.HashToken(raw)); err != nil {
		return fmt.Errorf("destroy session: %w", err)
	}
	return nil
}

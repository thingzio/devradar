package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/authn"
	"github.com/thingzio/devradar/pkg/ratelimit"
	"github.com/thingzio/devradar/pkg/secretbox"
)

const invitationTTL = 7 * 24 * time.Hour

var (
	ErrInvitationInvalid       = errors.New("invitation is invalid or no longer available")
	ErrInvitationExpired       = errors.New("invitation has expired")
	ErrInvitationEmailMismatch = errors.New("invitation email does not match signed-in user")
	ErrActiveMember            = errors.New("user is already an active account member")
	ErrRateLimited             = errors.New("invitation was sent too recently")
)

// InvitationDeliveryState is the bounded non-secret delivery state exposed to
// account administrators.
type InvitationDeliveryState string

const (
	// InvitationDeliveryQueued has not completed a provider attempt.
	InvitationDeliveryQueued InvitationDeliveryState = "queued"
	// InvitationDeliverySent was accepted by the provider.
	InvitationDeliverySent InvitationDeliveryState = "sent"
	// InvitationDeliveryRetrying has an attempted delivery pending retry.
	InvitationDeliveryRetrying InvitationDeliveryState = "retrying"
	// InvitationDeliveryFailed requires an administrator-initiated resend.
	InvitationDeliveryFailed InvitationDeliveryState = "failed"
)

// InvitationCreateOutcome describes the committed effect of an invitation
// create request without exposing token or delivery state.
type InvitationCreateOutcome string

const (
	// InvitationCreateUnchanged means an identical pending invitation existed.
	InvitationCreateUnchanged InvitationCreateOutcome = "unchanged"
	// InvitationCreateCreated means a new invitation and delivery were committed.
	InvitationCreateCreated InvitationCreateOutcome = "created"
	// InvitationCreateRoleChanged means the pending role and token were rotated.
	InvitationCreateRoleChanged InvitationCreateOutcome = "role_changed"
)

// InvitationRateLimits bounds committed create and role-change deliveries.
// Non-positive values disable the corresponding limit.
type InvitationRateLimits struct {
	AccountPerHour   int
	RecipientPerHour int
}

// Invitation is the non-secret account access grant shown to administrators
// and recipients. It never exposes the raw token or its stored hash.
type Invitation struct {
	ID             string
	AccountID      string
	AccountName    string
	Email          string
	Role           account.Role
	InvitedByEmail string
	DeliveryState  InvitationDeliveryState
	TokenVersion   int
	ExpiresAt      time.Time
	AcceptedAt     *time.Time
	RevokedAt      *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
	expired        bool
	sentRecently   bool
}

// CreateOrRefreshInvitation creates the one pending grant for an account/email.
// An exact duplicate is unchanged; a different role rotates the grant using the
// same semantics as an explicit role change. Invitation, encrypted outbox
// delivery, and audit attribution commit together.
func (s *Store) CreateOrRefreshInvitation(
	ctx context.Context,
	accountID, email string,
	role account.Role,
	actor account.Actor,
	requestID string,
	deliveryKey []byte,
) (*Invitation, error) {
	email = authn.NormalizeEmail(email)
	if !validInvitationEmail(email) || !role.Valid() {
		return nil, fmt.Errorf("invalid invitation recipient or role")
	}
	return s.rotateInvitation(ctx, accountID, "", email, role, actor, requestID, deliveryKey,
		nil, nil, false, false)
}

// CreateInvitation atomically detects duplicates, reserves durable delivery
// quota, and commits invitation, outbox, and audit state. Exact duplicates do
// not consume quota.
func (s *Store) CreateInvitation(
	ctx context.Context,
	accountID, email string,
	role account.Role,
	actor account.Actor,
	requestID string,
	deliveryKey []byte,
	limits InvitationRateLimits,
) (*Invitation, InvitationCreateOutcome, error) {
	email = authn.NormalizeEmail(email)
	if !validInvitationEmail(email) || !role.Valid() {
		return nil, "", fmt.Errorf("invalid invitation recipient or role")
	}
	var outcome InvitationCreateOutcome
	invitation, err := s.rotateInvitation(ctx, accountID, "", email, role, actor, requestID,
		deliveryKey, &limits, &outcome, false, false)
	if err != nil {
		return nil, "", err
	}
	return invitation, outcome, nil
}

// ResendInvitation rotates one pending invitation without changing its role.
// A durable timestamp check prevents sends more frequently than once a minute.
func (s *Store) ResendInvitation(
	ctx context.Context,
	accountID, invitationID string,
	actor account.Actor,
	requestID string,
	deliveryKey []byte,
) (*Invitation, error) {
	return s.rotateInvitation(ctx, accountID, invitationID, "", "", actor, requestID, deliveryKey,
		nil, nil, true, false)
}

// ChangeInvitationRole rotates one pending invitation while applying a new
// role, invalidating every previously delivered acceptance link.
func (s *Store) ChangeInvitationRole(
	ctx context.Context,
	accountID, invitationID string,
	role account.Role,
	actor account.Actor,
	requestID string,
	deliveryKey []byte,
) (*Invitation, error) {
	if !role.Valid() {
		return nil, fmt.Errorf("invalid invitation role")
	}
	return s.rotateInvitation(ctx, accountID, invitationID, "", role, actor, requestID, deliveryKey,
		nil, nil, false, true)
}

func (s *Store) rotateInvitation(
	ctx context.Context,
	accountID, invitationID, email string,
	role account.Role,
	actor account.Actor,
	requestID string,
	deliveryKey []byte,
	limits *InvitationRateLimits,
	createOutcome *InvitationCreateOutcome,
	resend bool,
	roleChange bool,
) (*Invitation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin invitation rotation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := lockActiveAccount(ctx, tx, accountID); err != nil {
		return nil, err
	}
	if err := requireAdminMembership(ctx, tx, accountID, actor); err != nil {
		return nil, err
	}

	var invitation Invitation
	var action string
	if resend || roleChange {
		if err := scanInvitation(tx.QueryRowContext(ctx, invitationSelect+`
			WHERE i.account_id=$1 AND i.id=$2 AND i.accepted_at IS NULL
			  AND i.revoked_at IS NULL FOR UPDATE OF i`, accountID, invitationID), &invitation); err != nil {
			return nil, invitationLookupError(err)
		}
		if resend && invitation.sentRecently {
			return nil, ErrRateLimited
		}
		email = invitation.Email
		if resend {
			role, action = invitation.Role, "invitation.resend"
		} else {
			action = "invitation.role_change"
		}
	} else {
		var active bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM devradar_account_member m
				JOIN devradar_user u ON u.id=m.user_id
				WHERE m.account_id=$1 AND u.email=$2 AND m.revoked_at IS NULL
			)`, accountID, email).Scan(&active); err != nil {
			return nil, fmt.Errorf("check active invitation member: %w", err)
		}
		if active {
			return nil, ErrActiveMember
		}
		err := scanInvitation(tx.QueryRowContext(ctx, invitationSelect+`
			WHERE i.account_id=$1 AND i.normalized_email=$2
			  AND i.accepted_at IS NULL AND i.revoked_at IS NULL FOR UPDATE OF i`, accountID, email), &invitation)
		switch {
		case err == nil:
			if invitation.Role == role {
				if createOutcome != nil {
					*createOutcome = InvitationCreateUnchanged
				}
				if err := tx.Commit(); err != nil {
					return nil, fmt.Errorf("commit duplicate invitation: %w", err)
				}
				return &invitation, nil
			}
			action = "invitation.role_change"
			if createOutcome != nil {
				*createOutcome = InvitationCreateRoleChanged
			}
		case errors.Is(err, sql.ErrNoRows):
			invitation.ID, err = newAuditUUID()
			if err != nil {
				return nil, err
			}
			invitation.AccountID = accountID
			invitation.Email = email
			invitation.TokenVersion = 0
			action = "invitation.create"
			if createOutcome != nil {
				*createOutcome = InvitationCreateCreated
			}
		default:
			return nil, fmt.Errorf("find pending invitation: %w", err)
		}
	}
	if limits != nil {
		if err := reserveInvitationQuota(ctx, tx, accountID, email, *limits); err != nil {
			return nil, err
		}
	}

	raw, err := authn.NewToken("")
	if err != nil {
		return nil, err
	}
	version := invitation.TokenVersion + 1
	idempotencyKey := fmt.Sprintf("account-invitation/%s/%d", invitation.ID, version)
	encrypted, err := secretbox.Seal(deliveryKey, []byte(raw), []byte(idempotencyKey))
	if err != nil {
		return nil, fmt.Errorf("encrypt invitation token: %w", err)
	}
	event := AuditEvent{Action: action, TargetType: "invitation", TargetID: invitation.ID,
		Outcome: "success", RequestID: requestID, Metadata: map[string]string{"role": string(role), "recipient": email}}
	metadata, err := validateAuditInput(accountID, actor, event)
	if err != nil {
		return nil, err
	}

	if invitation.TokenVersion == 0 {
		err = scanInvitation(tx.QueryRowContext(ctx, invitationInsertReturning,
			invitation.ID, accountID, email, role, actor.UserID, authn.HashToken(raw), version,
			invitationTTL.String()), &invitation)
	} else {
		err = scanInvitation(tx.QueryRowContext(ctx, invitationUpdateReturning,
			accountID, invitation.ID, role, actor.UserID, authn.HashToken(raw), version,
			invitationTTL.String()), &invitation)
	}
	if err != nil {
		return nil, fmt.Errorf("persist invitation: %w", err)
	}
	if _, err := s.EnqueueInvitationDelivery(ctx, tx, accountID, InvitationDelivery{
		InvitationID: invitation.ID, InvitationVersion: version, Recipient: email,
		EncryptedPayload: encrypted, IdempotencyKey: idempotencyKey,
	}); err != nil {
		return nil, err
	}
	if err := insertInvitationAudit(ctx, tx, accountID, actor, event, metadata); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit invitation rotation: %w", err)
	}
	return &invitation, nil
}

func reserveInvitationQuota(
	ctx context.Context,
	tx *sql.Tx,
	accountID, email string,
	limits InvitationRateLimits,
) error {
	allowed, err := ratelimit.Allow(ctx, tx, "invitation-account:"+accountID,
		limits.AccountPerHour, time.Hour)
	if err != nil {
		return fmt.Errorf("reserve account invitation quota: %w", err)
	}
	if !allowed {
		return ErrRateLimited
	}
	allowed, err = ratelimit.Allow(ctx, tx, "invitation-recipient:"+email,
		limits.RecipientPerHour, time.Hour)
	if err != nil {
		return fmt.Errorf("reserve recipient invitation quota: %w", err)
	}
	if !allowed {
		return ErrRateLimited
	}
	return nil
}

// RevokeInvitation terminates one account-owned pending grant.
func (s *Store) RevokeInvitation(ctx context.Context, accountID, invitationID string, actor account.Actor, requestID string) error {
	event := AuditEvent{Action: "invitation.revoke", TargetType: "invitation", TargetID: invitationID,
		Outcome: "success", RequestID: requestID}
	return s.withLockedAccountAudit(ctx, accountID, actor, event, func(tx *sql.Tx) (bool, error) {
		if err := requireAdminMembership(ctx, tx, accountID, actor); err != nil {
			return false, err
		}
		res, err := tx.ExecContext(ctx, `
			UPDATE devradar_account_invitation
			SET revoked_at=now(),revoked_by_user_id=$3,updated_at=now()
			WHERE account_id=$1 AND id=$2 AND accepted_at IS NULL AND revoked_at IS NULL`,
			accountID, invitationID, actor.UserID)
		if err != nil {
			return false, fmt.Errorf("revoke invitation: %w", err)
		}
		return exactlyOneRowChanged(res, "revoke invitation")
	})
}

// ListInvitations returns the pending account-owned grants in stable order.
func (s *Store) ListInvitations(ctx context.Context, accountID string) ([]Invitation, error) {
	rows, err := s.db.QueryContext(ctx, invitationListSelect+`
		WHERE i.account_id=$1 AND i.accepted_at IS NULL AND i.revoked_at IS NULL
		ORDER BY i.created_at,i.id`, accountID)
	if err != nil {
		return nil, fmt.Errorf("list invitations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var invitations []Invitation
	for rows.Next() {
		var invitation Invitation
		if err := scanListedInvitation(rows, &invitation); err != nil {
			return nil, fmt.Errorf("scan invitation: %w", err)
		}
		invitations = append(invitations, invitation)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate invitations: %w", err)
	}
	return invitations, nil
}

// PeekInvitation loads pending confirmation details by non-secret invitation
// identifier without mutating state, so email security scanners cannot consume
// the recipient's bearer token.
func (s *Store) PeekInvitation(ctx context.Context, invitationID string) (*Invitation, error) {
	var invitation Invitation
	err := scanInvitation(s.db.QueryRowContext(ctx, invitationSelect+`
		WHERE i.id=$1 AND i.accepted_at IS NULL AND i.revoked_at IS NULL`, invitationID), &invitation)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvitationInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("peek invitation: %w", err)
	}
	if invitation.expired {
		return nil, ErrInvitationExpired
	}
	return &invitation, nil
}

// AcceptInvitation commits identity, membership, invitation, and audit state.
// signedInUserID may be empty; the invitation itself proves ownership of its
// recipient email. consumed is true only for the transaction that changes the
// invitation from pending to accepted; callers must never create a session when
// it is false. Session creation intentionally remains a caller concern.
func (s *Store) AcceptInvitation(ctx context.Context, invitationID, raw, signedInUserID, requestID string) (*account.User, *account.Account, bool, error) {
	var accountID string
	if err := s.db.QueryRowContext(ctx, `SELECT account_id FROM devradar_account_invitation WHERE id=$1`, invitationID).Scan(&accountID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, false, ErrInvitationInvalid
		}
		return nil, nil, false, fmt.Errorf("locate invitation account: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, false, fmt.Errorf("begin invitation acceptance: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := lockActiveAccount(ctx, tx, accountID); err != nil {
		return nil, nil, false, err
	}

	var invitation Invitation
	var acceptedBy sql.NullString
	err = scanInvitationWithAcceptedBy(tx.QueryRowContext(ctx, invitationSelectAcceptedBy+`
		WHERE i.account_id=$1 AND i.id=$2 AND i.token_hash=$3 FOR UPDATE OF i`,
		accountID, invitationID, authn.HashToken(raw)), &invitation, &acceptedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, false, ErrInvitationInvalid
	}
	if err != nil {
		return nil, nil, false, fmt.Errorf("lock invitation: %w", err)
	}
	if invitation.RevokedAt != nil {
		return nil, nil, false, ErrInvitationInvalid
	}
	if invitation.AcceptedAt == nil && invitation.expired {
		return nil, nil, false, ErrInvitationExpired
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, invitation.Email); err != nil {
		return nil, nil, false, fmt.Errorf("lock invitation email: %w", err)
	}

	user, err := resolveInvitationUser(ctx, tx, invitation.Email, signedInUserID)
	if err != nil {
		return nil, nil, false, err
	}
	if invitation.AcceptedAt != nil {
		if !acceptedBy.Valid || acceptedBy.String != user.ID {
			return nil, nil, false, ErrInvitationInvalid
		}
		acct, err := accountByID(ctx, tx, accountID)
		if err != nil {
			return nil, nil, false, err
		}
		if err := tx.Commit(); err != nil {
			return nil, nil, false, fmt.Errorf("commit repeated invitation acceptance: %w", err)
		}
		return user, acct, false, nil
	}

	if err := linkInvitationIdentity(ctx, tx, user, invitation.Email); err != nil {
		return nil, nil, false, err
	}
	event := AuditEvent{Action: "invitation.accept", TargetType: "invitation", TargetID: invitation.ID,
		Outcome: "success", RequestID: requestID, Metadata: map[string]string{"role": string(invitation.Role), "recipient": invitation.Email}}
	acceptActor := account.Actor{Kind: account.ActorUser, UserID: user.ID}
	metadata, err := validateAuditInput(accountID, acceptActor, event)
	if err != nil {
		return nil, nil, false, err
	}
	inviterID, err := invitationInviterID(ctx, tx, invitation.ID)
	if err != nil {
		return nil, nil, false, err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO devradar_account_member
			(account_id,user_id,role,created_by_user_id,accepted_at,revoked_at,revoked_by_user_id,updated_at)
		VALUES($1,$2,$3,$4,now(),NULL,NULL,now())
		ON CONFLICT(account_id,user_id) DO UPDATE
		SET role=EXCLUDED.role,created_by_user_id=EXCLUDED.created_by_user_id,
		    accepted_at=now(),revoked_at=NULL,revoked_by_user_id=NULL,updated_at=now()`,
		accountID, user.ID, invitation.Role, nullStr(inviterID)); err != nil {
		return nil, nil, false, fmt.Errorf("create invitation membership: %w", err)
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE devradar_account_invitation
		SET accepted_at=now(),accepted_by_user_id=$3,updated_at=now()
		WHERE account_id=$1 AND id=$2 AND accepted_at IS NULL AND revoked_at IS NULL`, accountID, invitation.ID, user.ID)
	if err != nil {
		return nil, nil, false, fmt.Errorf("accept invitation: %w", err)
	}
	if changed, err := exactlyOneRowChanged(res, "accept invitation"); err != nil || !changed {
		return nil, nil, false, err
	}
	if err := insertInvitationAudit(ctx, tx, accountID, acceptActor, event, metadata); err != nil {
		return nil, nil, false, err
	}
	acct, err := accountByID(ctx, tx, accountID)
	if err != nil {
		return nil, nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, false, fmt.Errorf("commit invitation acceptance: %w", err)
	}
	return user, acct, true, nil
}

func resolveInvitationUser(ctx context.Context, tx *sql.Tx, email, signedInUserID string) (*account.User, error) {
	if signedInUserID != "" {
		user, err := userByID(ctx, tx, signedInUserID)
		if err != nil {
			return nil, err
		}
		if user.Status != "active" || user.Email != email {
			return nil, ErrInvitationEmailMismatch
		}
		return user, nil
	}
	user, err := userByEmail(ctx, tx, email)
	if err == nil {
		if user.Status != "active" {
			return nil, ErrForbidden
		}
		return user, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	var created account.User
	if err := scanUser(tx.QueryRowContext(ctx, `
		INSERT INTO devradar_user(email,email_verified_at,status)
		VALUES($1,now(),'active') RETURNING `+userColumns, email), &created); err != nil {
		return nil, fmt.Errorf("create invited user: %w", err)
	}
	return &created, nil
}

func linkInvitationIdentity(ctx context.Context, tx *sql.Tx, user *account.User, email string) error {
	var owner sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT user_id FROM devradar_identity WHERE provider='magiclink' AND subject=$1`, email).Scan(&owner)
	if err == nil {
		if !owner.Valid || owner.String != user.ID {
			return ErrInvitationEmailMismatch
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("read invitation identity: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO devradar_identity(tenant_id,user_id,provider,subject,email)
		VALUES(NULL,$1,'magiclink',$2,$2)`, user.ID, email); err != nil {
		return fmt.Errorf("link invitation identity: %w", err)
	}
	return nil
}

func invitationInviterID(ctx context.Context, tx *sql.Tx, invitationID string) (string, error) {
	var inviter sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT invited_by_user_id FROM devradar_account_invitation WHERE id=$1`, invitationID).Scan(&inviter); err != nil {
		return "", fmt.Errorf("read invitation inviter: %w", err)
	}
	return inviter.String, nil
}

func lockActiveAccount(ctx context.Context, tx *sql.Tx, accountID string) error {
	var status string
	err := tx.QueryRowContext(ctx, `SELECT status FROM devradar_tenant WHERE id=$1 FOR NO KEY UPDATE`, accountID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("lock invitation account: %w", err)
	}
	if status != "active" {
		return ErrNotFound
	}
	return nil
}

func accountByID(ctx context.Context, tx *sql.Tx, accountID string) (*account.Account, error) {
	var acct account.Account
	if err := scanAccount(tx.QueryRowContext(ctx, `SELECT `+accountColumns+` FROM devradar_tenant WHERE id=$1`, accountID), &acct); err != nil {
		return nil, fmt.Errorf("read invitation account: %w", err)
	}
	return &acct, nil
}

func insertInvitationAudit(ctx context.Context, tx *sql.Tx, accountID string, actor account.Actor, event AuditEvent, metadata []byte) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO devradar_audit_event
			(account_id,actor_kind,actor_user_id,actor_api_token_id,action,target_type,target_id,outcome,request_id,metadata)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)`,
		accountID, actor.Kind, nullStr(actor.UserID), nullStr(actor.APITokenID), event.Action,
		event.TargetType, event.TargetID, event.Outcome, event.RequestID, metadata); err != nil {
		return fmt.Errorf("insert invitation audit event: %w", err)
	}
	return nil
}

func validInvitationEmail(email string) bool {
	if len(email) < 3 || len(email) > 320 || strings.ContainsAny(email, "\r\n") {
		return false
	}
	parsed, err := mail.ParseAddress(email)
	return err == nil && parsed.Address == email
}

const invitationSelect = `
	SELECT i.id,i.account_id,t.name,i.normalized_email,i.role,
	       COALESCE(u.email,''),i.token_version,i.expires_at,i.accepted_at,
	       i.revoked_at,i.created_at,i.updated_at,i.expires_at<=clock_timestamp(),
	       i.updated_at>clock_timestamp()-interval '60 seconds'
	FROM devradar_account_invitation i
	JOIN devradar_tenant t ON t.id=i.account_id
	LEFT JOIN devradar_user u ON u.id=i.invited_by_user_id `

const invitationListSelect = `
	SELECT i.id,i.account_id,t.name,i.normalized_email,i.role,
	       COALESCE(u.email,''),i.token_version,i.expires_at,i.accepted_at,
	       i.revoked_at,i.created_at,i.updated_at,i.expires_at<=clock_timestamp(),
	       i.updated_at>clock_timestamp()-interval '60 seconds',
	       CASE
	         WHEN d.status='delivered' THEN 'sent'
	         WHEN d.status IN ('permanently_failed','canceled') THEN 'failed'
	         WHEN d.status IN ('pending','leased') AND (d.attempt_count>0 OR d.had_error) THEN 'retrying'
	         ELSE 'queued'
	       END
	FROM devradar_account_invitation i
	JOIN devradar_tenant t ON t.id=i.account_id
	LEFT JOIN devradar_user u ON u.id=i.invited_by_user_id
	LEFT JOIN LATERAL (
		SELECT status,attempt_count,last_error IS NOT NULL AS had_error
		FROM devradar_delivery_outbox
		WHERE account_id=i.account_id AND invitation_id=i.id
		  AND invitation_version=i.token_version
		ORDER BY created_at DESC,id DESC
		LIMIT 1
	) d ON true `

const invitationSelectAcceptedBy = `
	SELECT i.id,i.account_id,t.name,i.normalized_email,i.role,
	       COALESCE(u.email,''),i.token_version,i.expires_at,i.accepted_at,
	       i.revoked_at,i.created_at,i.updated_at,i.expires_at<=clock_timestamp(),
	       i.updated_at>clock_timestamp()-interval '60 seconds',i.accepted_by_user_id
	FROM devradar_account_invitation i
	JOIN devradar_tenant t ON t.id=i.account_id
	LEFT JOIN devradar_user u ON u.id=i.invited_by_user_id `

const invitationInsertReturning = `
	INSERT INTO devradar_account_invitation
		(id,account_id,normalized_email,role,invited_by_user_id,token_hash,token_version,expires_at)
	VALUES($1,$2,$3,$4,$5,$6,$7,now()+$8::interval)
	RETURNING id,account_id,(SELECT name FROM devradar_tenant WHERE id=$2),normalized_email,role,
	          (SELECT email FROM devradar_user WHERE id=$5),token_version,expires_at,accepted_at,
	          revoked_at,created_at,updated_at,expires_at<=clock_timestamp(),
	          updated_at>clock_timestamp()-interval '60 seconds'`

const invitationUpdateReturning = `
	UPDATE devradar_account_invitation
	SET role=$3,invited_by_user_id=$4,token_hash=$5,token_version=$6,
	    expires_at=now()+$7::interval,updated_at=now()
	WHERE account_id=$1 AND id=$2 AND accepted_at IS NULL AND revoked_at IS NULL
	RETURNING id,account_id,(SELECT name FROM devradar_tenant WHERE id=$1),normalized_email,role,
	          (SELECT email FROM devradar_user WHERE id=$4),token_version,expires_at,accepted_at,
	          revoked_at,created_at,updated_at,expires_at<=clock_timestamp(),
	          updated_at>clock_timestamp()-interval '60 seconds'`

type invitationScanner interface{ Scan(...any) error }

func scanInvitation(scanner invitationScanner, invitation *Invitation) error {
	var acceptedAt, revokedAt sql.NullTime
	if err := scanner.Scan(&invitation.ID, &invitation.AccountID, &invitation.AccountName,
		&invitation.Email, &invitation.Role, &invitation.InvitedByEmail, &invitation.TokenVersion,
		&invitation.ExpiresAt, &acceptedAt, &revokedAt, &invitation.CreatedAt, &invitation.UpdatedAt,
		&invitation.expired, &invitation.sentRecently); err != nil {
		return err
	}
	if acceptedAt.Valid {
		invitation.AcceptedAt = &acceptedAt.Time
	}
	if revokedAt.Valid {
		invitation.RevokedAt = &revokedAt.Time
	}
	return nil
}

func scanListedInvitation(scanner invitationScanner, invitation *Invitation) error {
	var acceptedAt, revokedAt sql.NullTime
	var deliveryState string
	if err := scanner.Scan(&invitation.ID, &invitation.AccountID, &invitation.AccountName,
		&invitation.Email, &invitation.Role, &invitation.InvitedByEmail, &invitation.TokenVersion,
		&invitation.ExpiresAt, &acceptedAt, &revokedAt, &invitation.CreatedAt, &invitation.UpdatedAt,
		&invitation.expired, &invitation.sentRecently, &deliveryState); err != nil {
		return err
	}
	invitation.DeliveryState = InvitationDeliveryState(deliveryState)
	if acceptedAt.Valid {
		invitation.AcceptedAt = &acceptedAt.Time
	}
	if revokedAt.Valid {
		invitation.RevokedAt = &revokedAt.Time
	}
	return nil
}

func scanInvitationWithAcceptedBy(scanner invitationScanner, invitation *Invitation, acceptedBy *sql.NullString) error {
	var acceptedAt, revokedAt sql.NullTime
	if err := scanner.Scan(&invitation.ID, &invitation.AccountID, &invitation.AccountName,
		&invitation.Email, &invitation.Role, &invitation.InvitedByEmail, &invitation.TokenVersion,
		&invitation.ExpiresAt, &acceptedAt, &revokedAt, &invitation.CreatedAt, &invitation.UpdatedAt,
		&invitation.expired, &invitation.sentRecently, acceptedBy); err != nil {
		return err
	}
	if acceptedAt.Valid {
		invitation.AcceptedAt = &acceptedAt.Time
	}
	if revokedAt.Valid {
		invitation.RevokedAt = &revokedAt.Time
	}
	return nil
}

func invitationLookupError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return fmt.Errorf("read invitation: %w", err)
}

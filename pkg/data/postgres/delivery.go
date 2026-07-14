package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	maxDeliveryLeaseLimit = 50
	maxDeliveryError      = 512
	maxProviderID         = 256
	maxDeliveryAttempts   = 10000
	maxDeliveryRetryDelay = 23 * time.Hour
)

var (
	// ErrStaleDeliveryLease means the delivery is no longer actively leased by
	// the caller. No state was changed.
	ErrStaleDeliveryLease = errors.New("stale delivery lease")
	// ErrStaleDeliveryInvitation means an enqueue or revalidation target is not
	// the exact current pending invitation identity.
	ErrStaleDeliveryInvitation = errors.New("stale delivery invitation")
	deliveryCredentialRE       = regexp.MustCompile(`(?i)(authorization\s*:\s*bearer|bearer)\s+\S+|\bre_[A-Za-z0-9_-]+`)
)

// Delivery is one leased encrypted outbox row. AccountID is carried explicitly
// so every revalidation and state transition remains account-filtered.
type Delivery struct {
	ID                  string
	AccountID           string
	Kind                string
	InvitationID        string
	InvitationVersion   int
	InvitationExpiresAt time.Time
	Recipient           string
	EncryptedPayload    string
	IdempotencyKey      string
	AttemptCount        int
	FirstAttemptAt      time.Time
	NextAttemptAt       time.Time
	LeaseOwner          string
	LeaseExpiresAt      time.Time
	CreatedAt           time.Time
}

// InvitationDelivery is the encrypted delivery identity inserted inside an
// invitation transaction. EncryptedPayload must contain no plaintext token.
type InvitationDelivery struct {
	InvitationID      string
	InvitationVersion int
	Recipient         string
	EncryptedPayload  string
	IdempotencyKey    string
}

// EnqueueInvitationDelivery locks and verifies the exact current invitation,
// then inserts its outbox row in the caller's transaction. Task 11 uses this
// inside WithAudit so invitation, delivery, and audit commit atomically.
func (s *Store) EnqueueInvitationDelivery(ctx context.Context, tx *sql.Tx, accountID string, delivery InvitationDelivery) (string, error) {
	if tx == nil {
		return "", fmt.Errorf("delivery transaction is required")
	}
	if accountID == "" || delivery.InvitationID == "" || delivery.InvitationVersion < 1 ||
		delivery.Recipient == "" || delivery.Recipient != strings.ToLower(strings.TrimSpace(delivery.Recipient)) {
		return "", ErrStaleDeliveryInvitation
	}
	var id string
	err := tx.QueryRowContext(ctx, `
		WITH invitation AS MATERIALIZED (
			SELECT id
			FROM devradar_account_invitation
			WHERE account_id=$1 AND id=$2 AND token_version=$3 AND normalized_email=$4
			  AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>clock_timestamp()
			FOR UPDATE
		)
		INSERT INTO devradar_delivery_outbox
			(account_id,kind,invitation_id,invitation_version,recipient,encrypted_payload,idempotency_key)
		SELECT $1,'account_invitation',$2,$3,$4,$5,$6 FROM invitation
		RETURNING id`, accountID, delivery.InvitationID, delivery.InvitationVersion,
		delivery.Recipient, delivery.EncryptedPayload, delivery.IdempotencyKey).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrStaleDeliveryInvitation
	}
	if err != nil {
		return "", fmt.Errorf("enqueue invitation delivery: %w", err)
	}
	return id, nil
}

// LeaseDeliveries atomically claims due pending work and expired leases. An
// attempt is counted when leased because a crashed worker may have reached the
// provider before losing its lease. The transaction commits before this method
// returns; callers never hold a database transaction during network I/O.
func (s *Store) LeaseDeliveries(ctx context.Context, owner string, limit int, leaseDuration time.Duration) ([]Delivery, error) {
	if limit <= 0 {
		return []Delivery{}, nil
	}
	owner = strings.TrimSpace(owner)
	if owner == "" || len(owner) > 128 {
		return nil, fmt.Errorf("delivery lease owner must be between 1 and 128 bytes")
	}
	if limit > maxDeliveryLeaseLimit {
		limit = maxDeliveryLeaseLimit
	}
	if leaseDuration <= 0 || leaseDuration > 15*time.Minute {
		return nil, fmt.Errorf("delivery lease duration must be positive and at most 15m")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin delivery lease: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		WITH poison AS MATERIALIZED (
			SELECT id
			FROM devradar_delivery_outbox
			WHERE attempt_count >= $1
			  AND ((status='pending' AND next_attempt_at<=clock_timestamp())
			    OR (status='leased' AND lease_expires_at<=clock_timestamp()))
			ORDER BY CASE WHEN status='pending' THEN next_attempt_at ELSE lease_expires_at END,created_at,id
			FOR UPDATE SKIP LOCKED
			LIMIT $2
		)
		UPDATE devradar_delivery_outbox d
		SET status='permanently_failed',encrypted_payload='',lease_owner=NULL,lease_expires_at=NULL,
		    provider_id=NULL,last_error='maximum delivery attempts exceeded',
		    permanently_failed_at=clock_timestamp(),updated_at=clock_timestamp()
		FROM poison p WHERE d.id=p.id`, maxDeliveryAttempts, maxDeliveryLeaseLimit); err != nil {
		return nil, fmt.Errorf("terminalize exhausted deliveries: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `
		WITH candidates AS MATERIALIZED (
			SELECT id,
			       CASE WHEN status='pending' THEN next_attempt_at ELSE lease_expires_at END AS due_at
			FROM devradar_delivery_outbox
			WHERE ((status='pending' AND next_attempt_at<=clock_timestamp())
			    OR (status='leased' AND lease_expires_at<=clock_timestamp()))
			  AND attempt_count < $4
			ORDER BY due_at,created_at,id
			FOR UPDATE SKIP LOCKED
			LIMIT $1
		), updated AS (
			UPDATE devradar_delivery_outbox d
			SET status='leased',
			    attempt_count=d.attempt_count+1,
			    first_attempt_at=COALESCE(d.first_attempt_at,clock_timestamp()),
			    lease_owner=$2,
			    lease_expires_at=clock_timestamp()+$3::interval,
			    updated_at=clock_timestamp()
			FROM candidates c
			WHERE d.id=c.id
			RETURNING d.id,d.account_id,d.kind,d.invitation_id,d.invitation_version,d.recipient,
			          d.encrypted_payload,d.idempotency_key,d.attempt_count,
			          d.first_attempt_at,d.next_attempt_at,d.lease_owner,
			          d.lease_expires_at,d.created_at,c.due_at
		)
		SELECT u.id,u.account_id,u.kind,u.invitation_id,u.invitation_version,i.expires_at,
		       u.recipient,u.encrypted_payload,u.idempotency_key,u.attempt_count,
		       u.first_attempt_at,u.next_attempt_at,u.lease_owner,u.lease_expires_at,u.created_at
		FROM updated u
		JOIN devradar_account_invitation i ON i.id=u.invitation_id
		ORDER BY u.due_at,u.created_at,u.id`, limit, owner, leaseDuration.String(), maxDeliveryAttempts)
	if err != nil {
		return nil, fmt.Errorf("lease deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	deliveries := make([]Delivery, 0, limit)
	for rows.Next() {
		var delivery Delivery
		if err := rows.Scan(&delivery.ID, &delivery.AccountID, &delivery.Kind, &delivery.InvitationID,
			&delivery.InvitationVersion, &delivery.InvitationExpiresAt, &delivery.Recipient,
			&delivery.EncryptedPayload, &delivery.IdempotencyKey, &delivery.AttemptCount,
			&delivery.FirstAttemptAt, &delivery.NextAttemptAt, &delivery.LeaseOwner,
			&delivery.LeaseExpiresAt, &delivery.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan leased delivery: %w", err)
		}
		deliveries = append(deliveries, delivery)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate leased deliveries: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close leased deliveries: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit delivery lease: %w", err)
	}
	return deliveries, nil
}

// DeliveryInvitationCurrent revalidates the invitation immediately before a
// worker sends. Missing, rotated, accepted, revoked, or expired invitations are
// stale and return false without exposing account data.
func (s *Store) DeliveryInvitationCurrent(ctx context.Context, accountID, invitationID string, version int) (bool, error) {
	var current bool
	err := s.db.QueryRowContext(ctx, `
		SELECT token_version=$3 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>clock_timestamp()
		FROM devradar_account_invitation WHERE account_id=$1 AND id=$2`, accountID, invitationID, version).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("revalidate delivery invitation: %w", err)
	}
	return current, nil
}

// CompleteDelivery records provider success for the exact active lease.
func (s *Store) CompleteDelivery(ctx context.Context, accountID, id, owner string, attempt int, providerID string) error {
	providerID = strings.TrimSpace(providerID)
	if providerID == "" || len(providerID) > maxProviderID {
		return fmt.Errorf("delivery provider ID must be between 1 and %d bytes", maxProviderID)
	}
	return s.transitionDelivery(ctx, `
		UPDATE devradar_delivery_outbox
		SET status='delivered',encrypted_payload='',lease_owner=NULL,lease_expires_at=NULL,
		    provider_id=$5,last_error=NULL,delivered_at=clock_timestamp(),updated_at=clock_timestamp()
		WHERE account_id=$1 AND id=$2 AND status='leased' AND lease_owner=$3 AND attempt_count=$4
		  AND lease_expires_at>clock_timestamp()`,
		accountID, id, owner, attempt, providerID)
}

// RetryDelivery releases the exact active lease and schedules a future attempt.
func (s *Store) RetryDelivery(ctx context.Context, accountID, id, owner string, attempt int, message string, delay time.Duration) error {
	if delay <= 0 || delay > maxDeliveryRetryDelay {
		return fmt.Errorf("delivery retry delay must be positive and at most 23h")
	}
	message = sanitizeDeliveryError(message)
	return s.transitionDelivery(ctx, `
		UPDATE devradar_delivery_outbox
		SET status='pending',lease_owner=NULL,lease_expires_at=NULL,
		    last_error=left(replace($5,recipient,'[redacted]'),512),
		    next_attempt_at=clock_timestamp()+$6::interval,updated_at=clock_timestamp()
		WHERE account_id=$1 AND id=$2 AND status='leased' AND lease_owner=$3 AND attempt_count=$4
		  AND lease_expires_at>clock_timestamp()`,
		accountID, id, owner, attempt, message, delay.String())
}

// PermanentlyFailDelivery records a non-retryable failure and scrubs ciphertext.
func (s *Store) PermanentlyFailDelivery(ctx context.Context, accountID, id, owner string, attempt int, message string) error {
	message = sanitizeDeliveryError(message)
	return s.transitionDelivery(ctx, `
		UPDATE devradar_delivery_outbox
		SET status='permanently_failed',encrypted_payload='',lease_owner=NULL,lease_expires_at=NULL,
		    last_error=left(replace($5,recipient,'[redacted]'),512),
		    permanently_failed_at=clock_timestamp(),updated_at=clock_timestamp()
		WHERE account_id=$1 AND id=$2 AND status='leased' AND lease_owner=$3 AND attempt_count=$4
		  AND lease_expires_at>clock_timestamp()`,
		accountID, id, owner, attempt, message)
}

// CancelDelivery records stale invitation work and scrubs ciphertext.
func (s *Store) CancelDelivery(ctx context.Context, accountID, id, owner string, attempt int, message string) error {
	message = sanitizeDeliveryError(message)
	return s.transitionDelivery(ctx, `
		UPDATE devradar_delivery_outbox
		SET status='canceled',encrypted_payload='',lease_owner=NULL,lease_expires_at=NULL,
		    last_error=left(replace($5,recipient,'[redacted]'),512),
		    canceled_at=clock_timestamp(),updated_at=clock_timestamp()
		WHERE account_id=$1 AND id=$2 AND status='leased' AND lease_owner=$3 AND attempt_count=$4
		  AND lease_expires_at>clock_timestamp()`,
		accountID, id, owner, attempt, message)
}

func (s *Store) transitionDelivery(ctx context.Context, query string, args ...any) error {
	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("transition delivery: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read delivery transition result: %w", err)
	}
	if changed != 1 {
		return ErrStaleDeliveryLease
	}
	return nil
}

func sanitizeDeliveryError(message string) string {
	message = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r >= 0x20 {
			return r
		}
		return -1
	}, message)
	message = deliveryCredentialRE.ReplaceAllString(message, "[redacted]")
	message = strings.TrimSpace(message)
	runes := []rune(message)
	if len(runes) > maxDeliveryError {
		message = string(runes[:maxDeliveryError])
	}
	if message == "" {
		return "delivery failed"
	}
	return message
}

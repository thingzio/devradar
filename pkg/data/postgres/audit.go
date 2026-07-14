package postgres

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/authn"
	"github.com/thingzio/devradar/pkg/data"
)

const (
	maxAuditActionChars     = 96
	maxAuditTargetTypeChars = 64
	maxAuditTargetIDChars   = 512
	maxAuditOutcomeChars    = 32
	maxAuditRequestIDChars  = 128
	maxAuditMetadataBytes   = 4096
)

// AuditEvent describes the durable attribution appended after a protected
// mutation succeeds in the same transaction.
type AuditEvent struct {
	Action     string
	TargetType string
	TargetID   string
	Outcome    string
	RequestID  string
	Metadata   map[string]string
}

var errAuditNoMutation = errors.New("audit: no mutation")

// ErrAPITokenLimit is returned when audited credential creation reaches the
// account's configured exact token cap.
var ErrAPITokenLimit = errors.New("API token limit reached for account")

type dbtx interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// WithAudit commits mutate and its success attribution atomically. A failure
// to append the event rolls back mutate. Callers must validate authorization
// and request data before entering this transaction.
func (s *Store) WithAudit(
	ctx context.Context,
	accountID string,
	actor account.Actor,
	event AuditEvent,
	mutate func(*sql.Tx) error,
) error {
	if mutate == nil {
		return fmt.Errorf("audit mutation is required")
	}
	return s.withAuditTarget(ctx, accountID, actor, event, func(tx *sql.Tx) (string, error) {
		return event.TargetID, mutate(tx)
	})
}

func (s *Store) withAuditTarget(
	ctx context.Context,
	accountID string,
	actor account.Actor,
	event AuditEvent,
	mutate func(*sql.Tx) (string, error),
) error {
	if mutate == nil {
		return fmt.Errorf("audit mutation is required")
	}
	metadata, err := validateAuditInput(accountID, actor, event)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin audited mutation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := authorizeAuditActor(ctx, tx, accountID, actor); err != nil {
		return err
	}
	resolvedTargetID, err := mutate(tx)
	if err != nil {
		if errors.Is(err, errAuditNoMutation) {
			if err := tx.Commit(); err != nil {
				return fmt.Errorf("commit audited no-op: %w", err)
			}
			return nil
		}
		return err
	}
	event.TargetID = resolvedTargetID
	if _, err := validateAuditInput(accountID, actor, event); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO devradar_audit_event
			(account_id,actor_kind,actor_user_id,actor_api_token_id,
			 action,target_type,target_id,outcome,request_id,metadata)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)`,
		accountID, actor.Kind, nullStr(actor.UserID), nullStr(actor.APITokenID),
		event.Action, event.TargetType, event.TargetID, event.Outcome, event.RequestID, metadata); err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit audited mutation: %w", err)
	}
	return nil
}

func authorizeAuditActor(ctx context.Context, tx *sql.Tx, accountID string, actor account.Actor) error {
	var authorized bool
	switch actor.Kind {
	case account.ActorUser:
		err := tx.QueryRowContext(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM devradar_account_member
				WHERE account_id=$1 AND user_id=$2 AND revoked_at IS NULL
			)`, accountID, actor.UserID).Scan(&authorized)
		if err != nil {
			return fmt.Errorf("authorize audit user actor: %w", err)
		}
	case account.ActorAPIToken:
		err := tx.QueryRowContext(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM devradar_api_token WHERE tenant_id=$1 AND id=$2
			)`, accountID, actor.APITokenID).Scan(&authorized)
		if err != nil {
			return fmt.Errorf("authorize audit api-token actor: %w", err)
		}
	case account.ActorPlatform:
		if actor.UserID == "" {
			return nil
		}
		err := tx.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM devradar_user WHERE id=$1)`, actor.UserID).Scan(&authorized)
		if err != nil {
			return fmt.Errorf("authorize audit platform actor: %w", err)
		}
	}
	if !authorized {
		return fmt.Errorf("audit actor is not authorized for account")
	}
	return nil
}

// UpdateAccountNameAudited changes the account display name with durable user
// or platform attribution.
func (s *Store) UpdateAccountNameAudited(ctx context.Context, accountID, name string, actor account.Actor, requestID string) error {
	if name == "" || name != strings.TrimSpace(name) || utf8.RuneCountInString(name) > 80 {
		return fmt.Errorf("invalid account name")
	}
	return s.WithAudit(ctx, accountID, actor, AuditEvent{
		Action: "account.name.update", TargetType: "account", TargetID: accountID,
		Outcome: "success", RequestID: requestID,
	}, func(tx *sql.Tx) error {
		changed, err := updateAccountName(ctx, tx, accountID, name)
		if err == nil && !changed {
			return errAuditNoMutation
		}
		return err
	})
}

func auditRepositoryTarget(repository string) string {
	if repository != "" && repository == strings.TrimSpace(repository) &&
		utf8.RuneCountInString(repository) <= maxAuditTargetIDChars {
		return repository
	}
	sum := sha256.Sum256([]byte(repository))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func updateAccountName(ctx context.Context, exec dbtx, accountID, name string) (bool, error) {
	res, err := exec.ExecContext(ctx, `
		UPDATE devradar_tenant SET name=$2,updated_at=now()
		WHERE id=$1 AND name IS DISTINCT FROM $2`, accountID, name)
	if err != nil {
		return false, fmt.Errorf("update account name: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("update account name rows affected: %w", err)
	}
	if n == 0 {
		var exists bool
		if err := exec.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM devradar_tenant WHERE id=$1)`, accountID).Scan(&exists); err != nil {
			return false, fmt.Errorf("check account name target: %w", err)
		}
		if !exists {
			return false, ErrNotFound
		}
	}
	return n > 0, nil
}

// SetMinSeverityAudited changes the account-wide default severity threshold.
func (s *Store) SetMinSeverityAudited(ctx context.Context, accountID, severity string, actor account.Actor, requestID string) error {
	if !data.ValidMinSeverity(severity) {
		return fmt.Errorf("invalid minimum severity %q", severity)
	}
	return s.WithAudit(ctx, accountID, actor, AuditEvent{
		Action: "account.min_severity.update", TargetType: "account", TargetID: accountID,
		Outcome: "success", RequestID: requestID,
	}, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE devradar_tenant SET min_severity=$2,updated_at=now()
			WHERE id=$1 AND min_severity IS DISTINCT FROM $2`, accountID, severity)
		if err != nil {
			return fmt.Errorf("set minimum severity: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("set minimum severity rows affected: %w", err)
		}
		if n == 0 {
			var exists bool
			if err := tx.QueryRowContext(ctx,
				`SELECT EXISTS(SELECT 1 FROM devradar_tenant WHERE id=$1)`, accountID).Scan(&exists); err != nil {
				return fmt.Errorf("check minimum severity target: %w", err)
			}
			if !exists {
				return ErrNotFound
			}
			return errAuditNoMutation
		}
		return nil
	})
}

// CreateAPITokenAudited generates an account credential and appends its audit
// event in the same transaction. Only the hash crosses the database boundary.
func (s *Store) CreateAPITokenAudited(
	ctx context.Context,
	accountID, name string,
	ttl time.Duration,
	maxTokens int,
	actor account.Actor,
	requestID string,
) (string, error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", fmt.Errorf("generate api token: %w", err)
	}
	raw := "dr_" + hex.EncodeToString(secret[:])
	tokenID, err := newAuditUUID()
	if err != nil {
		return "", fmt.Errorf("generate api token id: %w", err)
	}
	var expiresAt any
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl).UTC()
	}
	err = s.WithAudit(ctx, accountID, actor, AuditEvent{
		Action: "api_token.create", TargetType: "api_token", TargetID: tokenID,
		Outcome: "success", RequestID: requestID,
	}, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`SELECT pg_advisory_xact_lock(hashtext($1))`, accountID); err != nil {
			return fmt.Errorf("acquire token admission lock: %w", err)
		}
		res, err := tx.ExecContext(ctx, `
			INSERT INTO devradar_api_token
				(id,tenant_id,name,token_hash,expires_at,created_by_user_id)
			SELECT $1,$2,$3,$4,$5,$6
			WHERE $7 <= 0
			   OR (SELECT count(*) FROM devradar_api_token WHERE tenant_id=$2) < $7`,
			tokenID, accountID, name, authn.HashToken(raw), expiresAt,
			nullStr(actor.UserID), maxTokens)
		if err != nil {
			return fmt.Errorf("create api token: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("create api token rows affected: %w", err)
		}
		if n == 0 {
			return ErrAPITokenLimit
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return raw, nil
}

func newAuditUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	h := hex.EncodeToString(raw[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// RevokeAPITokenAudited deletes only an account-owned credential and records
// its stable token UUID as the target.
func (s *Store) RevokeAPITokenAudited(ctx context.Context, accountID, tokenID string, actor account.Actor, requestID string) error {
	return s.WithAudit(ctx, accountID, actor, AuditEvent{
		Action: "api_token.revoke", TargetType: "api_token", TargetID: tokenID,
		Outcome: "success", RequestID: requestID,
	}, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`DELETE FROM devradar_api_token WHERE id=$1 AND tenant_id=$2`, tokenID, accountID)
		if err != nil {
			return fmt.Errorf("revoke api token: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("revoke api token rows affected: %w", err)
		}
		if n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func validateAuditInput(accountID string, actor account.Actor, event AuditEvent) ([]byte, error) {
	if accountID == "" {
		return nil, fmt.Errorf("audit account id is required")
	}
	switch actor.Kind {
	case account.ActorUser:
		if actor.UserID == "" || actor.APITokenID != "" {
			return nil, fmt.Errorf("invalid user audit actor")
		}
	case account.ActorAPIToken:
		if actor.APITokenID == "" || actor.UserID != "" {
			return nil, fmt.Errorf("invalid api-token audit actor")
		}
	case account.ActorPlatform:
		if actor.APITokenID != "" {
			return nil, fmt.Errorf("invalid platform audit actor")
		}
	default:
		return nil, fmt.Errorf("invalid audit actor kind %q", actor.Kind)
	}
	for _, field := range []struct {
		name  string
		value string
		max   int
	}{
		{"action", event.Action, maxAuditActionChars},
		{"target type", event.TargetType, maxAuditTargetTypeChars},
		{"target id", event.TargetID, maxAuditTargetIDChars},
		{"outcome", event.Outcome, maxAuditOutcomeChars},
		{"request id", event.RequestID, maxAuditRequestIDChars},
	} {
		if field.value == "" || field.value != strings.TrimSpace(field.value) ||
			utf8.RuneCountInString(field.value) > field.max {
			return nil, fmt.Errorf("invalid audit %s", field.name)
		}
	}
	for key, value := range event.Metadata {
		normalized := strings.ToLower(key)
		for _, forbidden := range []string{
			"token", "secret", "session", "login", "invitation", "payload", "envelope", "ciphertext", "vex",
		} {
			if strings.Contains(normalized, forbidden) {
				return nil, fmt.Errorf("audit metadata key %q may contain secret material", key)
			}
		}
		if strings.Contains(value, "dr_") || strings.Contains(value, "enc:") {
			return nil, fmt.Errorf("audit metadata value for %q may contain secret material", key)
		}
	}
	if event.Metadata == nil {
		event.Metadata = map[string]string{}
	}
	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return nil, fmt.Errorf("encode audit metadata: %w", err)
	}
	if len(metadata) > maxAuditMetadataBytes {
		return nil, fmt.Errorf("audit metadata exceeds %d bytes", maxAuditMetadataBytes)
	}
	return metadata, nil
}

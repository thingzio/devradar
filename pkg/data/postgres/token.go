// Copyright 2026 Thingz LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/authn"
	"github.com/thingzio/devradar/pkg/secretbox"
)

const tokenFlashTTL = 2 * time.Minute

// APITokenInfo is account credential metadata. It never contains the secret.
type APITokenInfo struct {
	ID        string
	Name      string
	LastUsed  *time.Time
	ExpiresAt *time.Time
	CreatedAt time.Time
}

// ListAPITokens returns account token metadata only to an active account admin
// or an authenticated platform actor.
func (s *Store) ListAPITokens(ctx context.Context, accountID string, actor account.Actor) ([]APITokenInfo, error) {
	if err := authorizeTokenManager(ctx, s.db, accountID, actor); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id,name,last_used_at,expires_at,created_at
		FROM devradar_api_token
		WHERE tenant_id=$1
		ORDER BY created_at DESC,id DESC`, accountID)
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []APITokenInfo
	for rows.Next() {
		var token APITokenInfo
		var lastUsed, expiresAt sql.NullTime
		if err := rows.Scan(&token.ID, &token.Name, &lastUsed, &expiresAt, &token.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan api token: %w", err)
		}
		if lastUsed.Valid {
			token.LastUsed = &lastUsed.Time
		}
		if expiresAt.Valid {
			token.ExpiresAt = &expiresAt.Time
		}
		out = append(out, token)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate api tokens: %w", err)
	}
	return out, nil
}

// CreateAPIToken atomically creates an account credential, appends its user
// audit event, and stores its one-time display value for the exact session and
// account. sessionHash must be authn.HashToken(rawSession), never a raw cookie.
func (s *Store) CreateAPIToken(
	ctx context.Context,
	accountID, userID, sessionHash, name string,
	ttl time.Duration,
	maxTokens int,
	requestID string,
	key []byte,
) (string, error) {
	raw, err := authn.NewToken("dr_")
	if err != nil {
		return "", fmt.Errorf("generate api token: %w", err)
	}
	tokenID, err := newAuditUUID()
	if err != nil {
		return "", fmt.Errorf("generate api token id: %w", err)
	}
	stored, err := secretbox.Seal(key, []byte(raw), tokenFlashAdditionalData(sessionHash, accountID))
	if err != nil {
		return "", fmt.Errorf("encrypt token flash: %w", err)
	}
	event := AuditEvent{
		Action: "api_token.create", TargetType: "api_token", TargetID: tokenID,
		Outcome: "success", RequestID: requestID,
	}
	actor := account.Actor{Kind: account.ActorUser, UserID: userID}
	metadata, err := validateAuditInput(accountID, actor, event)
	if err != nil {
		return "", err
	}
	var expiresAt any
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl).UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin token create: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var lockedAccountID, accountStatus string
	if err := tx.QueryRowContext(ctx, `
		SELECT id,status FROM devradar_tenant WHERE id=$1 FOR NO KEY UPDATE`, accountID).
		Scan(&lockedAccountID, &accountStatus); errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	} else if err != nil {
		return "", fmt.Errorf("lock token account: %w", err)
	}
	if accountStatus != "active" {
		return "", ErrNotFound
	}
	if _, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtext($1))`, accountID); err != nil {
		return "", fmt.Errorf("acquire token admission lock: %w", err)
	}
	var sessionUserID, sessionAccountID sql.NullString
	if err := tx.QueryRowContext(ctx, `
		SELECT user_id,active_account_id
		FROM devradar_session
		WHERE id=$1 AND expires_at>now()
		FOR UPDATE`, sessionHash).Scan(&sessionUserID, &sessionAccountID); errors.Is(err, sql.ErrNoRows) {
		return "", ErrForbidden
	} else if err != nil {
		return "", fmt.Errorf("lock token creator session: %w", err)
	}
	if !sessionUserID.Valid || sessionUserID.String != userID ||
		!sessionAccountID.Valid || sessionAccountID.String != accountID {
		return "", ErrForbidden
	}
	var authorized bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1
			FROM devradar_tenant t
			JOIN devradar_account_member m ON m.account_id=t.id
			JOIN devradar_user u ON u.id=m.user_id
			WHERE t.id=$1 AND t.status='active'
			  AND u.id=$2 AND u.status='active'
			  AND m.user_id=$2 AND m.role='admin' AND m.revoked_at IS NULL
		)`, accountID, userID).Scan(&authorized); err != nil {
		return "", fmt.Errorf("authorize token creator session: %w", err)
	}
	if !authorized {
		return "", ErrForbidden
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO devradar_api_token
			(id,tenant_id,name,token_hash,expires_at,created_by_user_id)
		SELECT $1,$2,$3,$4,$5,$6
		WHERE $7 <= 0
		   OR (SELECT count(*) FROM devradar_api_token WHERE tenant_id=$2) < $7`,
		tokenID, accountID, name, authn.HashToken(raw), expiresAt, userID, maxTokens)
	if err != nil {
		return "", fmt.Errorf("create api token: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return "", fmt.Errorf("create api token rows affected: %w", err)
	}
	if rows == 0 {
		return "", ErrAPITokenLimit
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO devradar_session_token_flash (session_id,account_id,value,expires_at)
		VALUES ($1,$2,$3,now()+$4::interval)
		ON CONFLICT (session_id,account_id) DO UPDATE
		SET value=EXCLUDED.value,expires_at=EXCLUDED.expires_at`,
		sessionHash, accountID, stored, tokenFlashTTL.String()); err != nil {
		return "", fmt.Errorf("store token flash: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO devradar_audit_event
			(account_id,actor_kind,actor_user_id,actor_api_token_id,
			 action,target_type,target_id,outcome,request_id,metadata)
		VALUES ($1,$2,$3,NULL,$4,$5,$6,$7,$8,$9::jsonb)`,
		accountID, actor.Kind, userID, event.Action, event.TargetType, event.TargetID,
		event.Outcome, event.RequestID, metadata); err != nil {
		return "", fmt.Errorf("insert token create audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit token create: %w", err)
	}
	return tokenID, nil
}

// ConsumeTokenFlash authenticates and deletes the exact session/account flash
// in one transaction. Authentication failure retains the row for recovery with
// the correct key; successful plaintext is returned at most once.
func (s *Store) ConsumeTokenFlash(ctx context.Context, sessionHash, accountID string, key []byte) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin token flash consume: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var stored string
	err = tx.QueryRowContext(ctx, `
		SELECT f.value
		FROM devradar_session_token_flash f
		JOIN devradar_session s
		  ON s.id=f.session_id AND s.active_account_id=f.account_id AND s.expires_at>now()
		WHERE f.session_id=$1 AND f.account_id=$2 AND f.expires_at>now()
		FOR UPDATE OF s,f`, sessionHash, accountID).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read token flash: %w", err)
	}
	plaintext, err := secretbox.Open(key, stored, tokenFlashAdditionalData(sessionHash, accountID))
	if err != nil {
		return "", fmt.Errorf("decrypt token flash: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM devradar_session_token_flash
		WHERE session_id=$1 AND account_id=$2`, sessionHash, accountID); err != nil {
		return "", fmt.Errorf("delete token flash: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit token flash consume: %w", err)
	}
	return string(plaintext), nil
}

// RevokeAPIToken deletes an account-owned credential and appends its audit
// event atomically. User actors must be active account admins; the platform
// actor compatibility path remains for the existing operator console.
func (s *Store) RevokeAPIToken(ctx context.Context, accountID, tokenID string, actor account.Actor, requestID string) error {
	event := AuditEvent{
		Action: "api_token.revoke", TargetType: "api_token", TargetID: tokenID,
		Outcome: "success", RequestID: requestID,
	}
	if actor.Kind == account.ActorUser {
		return s.withLockedAccountAudit(ctx, accountID, actor, event, func(tx *sql.Tx) (bool, error) {
			if err := requireAdminMembership(ctx, tx, accountID, actor); err != nil {
				return false, err
			}
			return deleteAPIToken(ctx, tx, accountID, tokenID)
		})
	}
	if actor.Kind != account.ActorPlatform {
		return ErrForbidden
	}
	return s.WithAudit(ctx, accountID, actor, event, func(tx *sql.Tx) error {
		_, err := deleteAPIToken(ctx, tx, accountID, tokenID)
		return err
	})
}

// PurgeLegacyTokenFlashes removes the account-keyed compatibility secrets at
// the explicit sharing cutover. Task 11/13 owns invoking it after reconciliation
// and old-revision traffic reaches zero.
func (s *Store) PurgeLegacyTokenFlashes(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM devradar_token_flash`); err != nil {
		return fmt.Errorf("purge legacy token flashes: %w", err)
	}
	return nil
}

func authorizeTokenManager(ctx context.Context, exec dbtx, accountID string, actor account.Actor) error {
	var authorized bool
	switch actor.Kind {
	case account.ActorUser:
		if err := exec.QueryRowContext(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM devradar_tenant t
				JOIN devradar_account_member m ON m.account_id=t.id
				JOIN devradar_user u ON u.id=m.user_id
				WHERE t.id=$1 AND t.status='active'
				  AND u.id=$2 AND u.status='active'
				  AND m.role='admin' AND m.revoked_at IS NULL
			)`, accountID, actor.UserID).Scan(&authorized); err != nil {
			return fmt.Errorf("authorize token metadata: %w", err)
		}
	case account.ActorPlatform:
		if actor.UserID == "" {
			return ErrForbidden
		}
		if err := exec.QueryRowContext(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM devradar_tenant t,devradar_user u
				WHERE t.id=$1 AND u.id=$2 AND u.status='active'
			)`, accountID, actor.UserID).Scan(&authorized); err != nil {
			return fmt.Errorf("authorize platform token metadata: %w", err)
		}
	default:
		return ErrForbidden
	}
	if !authorized {
		return ErrForbidden
	}
	return nil
}

func deleteAPIToken(ctx context.Context, exec dbtx, accountID, tokenID string) (bool, error) {
	res, err := exec.ExecContext(ctx,
		`DELETE FROM devradar_api_token WHERE tenant_id=$1 AND id=$2`, accountID, tokenID)
	if err != nil {
		return false, fmt.Errorf("revoke api token: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("revoke api token rows affected: %w", err)
	}
	if rows == 0 {
		return false, ErrNotFound
	}
	return true, nil
}

func tokenFlashAdditionalData(sessionHash, accountID string) []byte {
	return []byte("devradar/token-flash/v1\x00" + sessionHash + "\x00" + accountID)
}

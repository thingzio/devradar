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

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

func TestAccountIdentityMigrationBackfill(t *testing.T) {
	st := isolatedStoreAtVersion(t, 29)
	legacyID := seedLegacyTenantIdentityAndSession(t, st)
	applyMigrationFile(t, st, "sql/migrations/030_account_identity.sql")

	var accountID, userID, role string
	err := st.DB().QueryRow(`
		SELECT m.account_id, m.user_id, m.role
		FROM devradar_account_member m
		JOIN devradar_user u ON u.id=m.user_id
		WHERE u.legacy_tenant_id=$1`, legacyID).Scan(&accountID, &userID, &role)
	if err != nil || accountID != legacyID || userID == legacyID || role != "admin" {
		t.Fatalf("backfill = %s %s %s, err=%v", accountID, userID, role, err)
	}

	var identityUserID, sessionUserID, activeAccountID, accountName string
	if err := st.DB().QueryRow(`
		SELECT i.user_id, s.user_id, s.active_account_id, t.name
		FROM devradar_identity i
		JOIN devradar_session s ON s.tenant_id=i.tenant_id
		JOIN devradar_tenant t ON t.id=i.tenant_id
		WHERE i.tenant_id=$1`, legacyID).Scan(
		&identityUserID, &sessionUserID, &activeAccountID, &accountName); err != nil {
		t.Fatalf("read auth backfill: %v", err)
	}
	if identityUserID != userID || sessionUserID != userID || activeAccountID != legacyID {
		t.Fatalf("auth backfill = identity %s session %s account %s, want %s %s",
			identityUserID, sessionUserID, activeAccountID, userID, legacyID)
	}
	if accountName == "" {
		t.Fatal("account name was not backfilled")
	}

	var inviteUserID string
	if err := st.DB().QueryRow(`
		INSERT INTO devradar_user (email) VALUES ($1) RETURNING id`,
		"invite-"+randID(t)[:8]+"@example.com").Scan(&inviteUserID); err != nil {
		t.Fatalf("seed invitation user: %v", err)
	}
	if _, err := st.DB().Exec(`
		INSERT INTO devradar_identity (tenant_id,user_id,provider,subject,email)
		VALUES (NULL,$1,'github',$2,$3)`, inviteUserID, randID(t), "invite@example.com"); err != nil {
		t.Fatalf("insert identity without compatibility tenant: %v", err)
	}
	if _, err := st.DB().Exec(`
		INSERT INTO devradar_session (id,tenant_id,user_id,active_account_id,expires_at)
		VALUES ($1,NULL,$2,NULL,now()+interval '1 hour')`, randID(t), inviteUserID); err != nil {
		t.Fatalf("insert chooser session without compatibility tenant: %v", err)
	}
	if _, err := st.DB().Exec(`
		INSERT INTO devradar_api_token (tenant_id,name,token_hash,created_by_user_id)
		VALUES ($1,'migration-test',$2,$3)`, legacyID, randID(t), userID); err != nil {
		t.Fatalf("insert attributed API token: %v", err)
	}

	for indexName, wantColumns := range map[string][]string{
		"idx_devradar_account_member_user_active":         {"user_id", "account_id"},
		"idx_devradar_account_member_account_role_active": {"account_id", "role"},
	} {
		var columns []string
		var predicate string
		if err := st.DB().QueryRow(`
			SELECT array_agg(a.attname ORDER BY k.ordinality),
			       pg_get_expr(i.indpred,i.indrelid)
			FROM pg_index i
			JOIN pg_class c ON c.oid=i.indexrelid
			JOIN LATERAL unnest(i.indkey) WITH ORDINALITY k(attnum,ordinality) ON true
			JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum
			WHERE c.relnamespace=current_schema()::regnamespace AND c.relname=$1
			GROUP BY i.indpred,i.indrelid`, indexName).Scan(pq.Array(&columns), &predicate); err != nil {
			t.Fatalf("read membership index %s: %v", indexName, err)
		}
		if strings.Join(columns, ",") != strings.Join(wantColumns, ",") {
			t.Fatalf("index %s columns = %v, want %v", indexName, columns, wantColumns)
		}
		if strings.ReplaceAll(predicate, " ", "") != "(revoked_atISNULL)" {
			t.Fatalf("index %s predicate = %q, want revoked_at IS NULL", indexName, predicate)
		}
	}
}

func TestAccountIdentityMigrationAccountNameConstraint(t *testing.T) {
	st := isolatedStoreAtVersion(t, 29)
	ctx := context.Background()
	var spacedAccountID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_tenant (email) VALUES ('  spaced@example.com  ') RETURNING id`).
		Scan(&spacedAccountID); err != nil {
		t.Fatalf("seed spaced legacy email: %v", err)
	}
	firstAccountID := seedLegacyTenantIdentityAndSession(t, st)
	secondAccountID := seedLegacyTenantIdentityAndSession(t, st)
	applyMigrationFile(t, st, "sql/migrations/030_account_identity.sql")

	var migratedName string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT name FROM devradar_tenant WHERE id=$1`, spacedAccountID).Scan(&migratedName); err != nil {
		t.Fatalf("read migrated account name: %v", err)
	}
	if migratedName != "spaced@example.com" {
		t.Fatalf("migrated account name = %q, want trimmed email", migratedName)
	}

	for _, valid := range []string{"", "same display name", strings.Repeat("界", 80)} {
		if _, err := st.DB().ExecContext(ctx,
			`UPDATE devradar_tenant SET name=$2 WHERE id=$1`, firstAccountID, valid); err != nil {
			t.Fatalf("valid account name %q rejected: %v", valid, err)
		}
	}
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_tenant SET name='same display name' WHERE id IN ($1,$2)`,
		firstAccountID, secondAccountID); err != nil {
		t.Fatalf("valid duplicate display name rejected: %v", err)
	}
	for _, invalid := range []string{" ", " leading", "trailing ", strings.Repeat("a", 81)} {
		if _, err := st.DB().ExecContext(ctx,
			`UPDATE devradar_tenant SET name=$2 WHERE id=$1`, firstAccountID, invalid); err == nil {
			t.Fatalf("invalid account name %q accepted", invalid)
		}
	}
}

func TestAccountIdentityMigrationCascadePreservesSharedUser(t *testing.T) {
	st := isolatedStoreAtVersion(t, 29)
	firstAccountID := seedLegacyTenantIdentityAndSession(t, st)
	secondAccountID := seedLegacyTenantIdentityAndSession(t, st)
	applyMigrationFile(t, st, "sql/migrations/030_account_identity.sql")

	var userID string
	if err := st.DB().QueryRow(`
		SELECT id FROM devradar_user WHERE legacy_tenant_id=$1`, firstAccountID).Scan(&userID); err != nil {
		t.Fatalf("find migrated user: %v", err)
	}
	if _, err := st.DB().Exec(`
		INSERT INTO devradar_account_member (account_id,user_id,role)
		VALUES ($1,$2,'reader')`, secondAccountID, userID); err != nil {
		t.Fatalf("add shared membership: %v", err)
	}
	if _, err := st.DB().Exec(`DELETE FROM devradar_tenant WHERE id=$1`, firstAccountID); err != nil {
		t.Fatalf("delete first account: %v", err)
	}

	var users, memberships int
	if err := st.DB().QueryRow(`SELECT count(*) FROM devradar_user WHERE id=$1`, userID).Scan(&users); err != nil {
		t.Fatalf("count shared user: %v", err)
	}
	if err := st.DB().QueryRow(`
		SELECT count(*) FROM devradar_account_member WHERE account_id=$1 AND user_id=$2`,
		secondAccountID, userID).Scan(&memberships); err != nil {
		t.Fatalf("count remaining membership: %v", err)
	}
	if users != 1 || memberships != 1 {
		t.Fatalf("after account cascade users=%d memberships=%d, want 1/1", users, memberships)
	}
}

func TestAccountStoreIsolationAndAccess(t *testing.T) {
	st := isolatedStoreAtVersion(t, 29)
	firstAccountID := seedLegacyTenantIdentityAndSession(t, st)
	secondAccountID := seedLegacyTenantIdentityAndSession(t, st)
	applyMigrationFile(t, st, "sql/migrations/030_account_identity.sql")
	ctx := context.Background()

	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_tenant SET name='same display name' WHERE id IN ($1,$2)`,
		firstAccountID, secondAccountID); err != nil {
		t.Fatalf("set identical account names: %v", err)
	}
	var firstUserID, secondUserID string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT id FROM devradar_user WHERE legacy_tenant_id=$1`, firstAccountID).Scan(&firstUserID); err != nil {
		t.Fatalf("find first user: %v", err)
	}
	if err := st.DB().QueryRowContext(ctx,
		`SELECT id FROM devradar_user WHERE legacy_tenant_id=$1`, secondAccountID).Scan(&secondUserID); err != nil {
		t.Fatalf("find second user: %v", err)
	}

	first, err := st.GetAccount(ctx, firstAccountID)
	if err != nil || first.ID != firstAccountID || first.Name != "same display name" {
		t.Fatalf("GetAccount(first) = %#v, %v", first, err)
	}
	second, err := st.GetAccount(ctx, secondAccountID)
	if err != nil || second.ID != secondAccountID || second.Name != first.Name {
		t.Fatalf("GetAccount(second) = %#v, %v", second, err)
	}
	user, err := st.GetUser(ctx, firstUserID)
	if err != nil || user.ID != firstUserID {
		t.Fatalf("GetUser() = %#v, %v", user, err)
	}

	roleChangedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_account_member
			(account_id,user_id,role,updated_at)
		VALUES ($1,$2,'editor',$3)`, secondAccountID, firstUserID, roleChangedAt); err != nil {
		t.Fatalf("add second membership: %v", err)
	}
	access, err := st.GetAccess(ctx, firstUserID, secondAccountID)
	if err != nil || access.Actor.ID != firstUserID || access.Account.ID != secondAccountID ||
		access.Membership.Role != account.RoleEditor || !access.Membership.UpdatedAt.Equal(roleChangedAt) {
		t.Fatalf("GetAccess() = %#v, %v", access, err)
	}
	if _, err := st.GetAccess(ctx, secondUserID, firstAccountID); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("cross-account GetAccess error = %v, want ErrNotFound", err)
	}

	accounts, err := st.ListUserAccounts(ctx, firstUserID)
	if err != nil || len(accounts) != 2 {
		t.Fatalf("ListUserAccounts() = %#v, %v", accounts, err)
	}
	if accounts[0].Account.ID == accounts[1].Account.ID {
		t.Fatalf("identically named accounts collapsed: %#v", accounts)
	}

	if _, err := st.DB().ExecContext(ctx, `
		UPDATE devradar_account_member
		SET revoked_at=now(),updated_at=now()
		WHERE account_id=$1 AND user_id=$2`, secondAccountID, firstUserID); err != nil {
		t.Fatalf("revoke membership: %v", err)
	}
	if _, err := st.GetAccess(ctx, firstUserID, secondAccountID); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("revoked GetAccess error = %v, want ErrNotFound", err)
	}
	accounts, err = st.ListUserAccounts(ctx, firstUserID)
	if err != nil || len(accounts) != 1 || accounts[0].Account.ID != firstAccountID {
		t.Fatalf("accounts after revoke = %#v, %v", accounts, err)
	}

	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_user SET status='suspended' WHERE id=$1`, firstUserID); err != nil {
		t.Fatalf("suspend user: %v", err)
	}
	if _, err := st.GetAccess(ctx, firstUserID, firstAccountID); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("suspended-user GetAccess error = %v, want ErrNotFound", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_user SET status='active' WHERE id=$1`, firstUserID); err != nil {
		t.Fatalf("reactivate user: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_tenant SET status='suspended' WHERE id=$1`, firstAccountID); err != nil {
		t.Fatalf("suspend account: %v", err)
	}
	if _, err := st.GetAccess(ctx, firstUserID, firstAccountID); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("suspended-account GetAccess error = %v, want ErrNotFound", err)
	}
}

func TestAccountStoreReconcileLegacy(t *testing.T) {
	st := isolatedStoreAtVersion(t, 29)
	applyMigrationFile(t, st, "sql/migrations/030_account_identity.sql")
	ctx := context.Background()
	legacyID := seedLegacyTenantIdentityAndSession(t, st)

	if err := st.ReconcileLegacyAccount(ctx, legacyID); err != nil {
		t.Fatalf("reconcile legacy account: %v", err)
	}
	if err := st.ReconcileLegacyAccount(ctx, legacyID); err != nil {
		t.Fatalf("reconcile legacy account again: %v", err)
	}

	var userID, identityUserID, sessionUserID, activeAccountID, name string
	if err := st.DB().QueryRowContext(ctx, `
		SELECT u.id,i.user_id,s.user_id,s.active_account_id,t.name
		FROM devradar_tenant t
		JOIN devradar_user u ON u.legacy_tenant_id=t.id
		JOIN devradar_identity i ON i.tenant_id=t.id
		JOIN devradar_session s ON s.tenant_id=t.id
		WHERE t.id=$1`, legacyID).Scan(
		&userID, &identityUserID, &sessionUserID, &activeAccountID, &name); err != nil {
		t.Fatalf("read reconciled legacy account: %v", err)
	}
	if userID == legacyID || identityUserID != userID || sessionUserID != userID ||
		activeAccountID != legacyID || name == "" {
		t.Fatalf("reconcile = user %s identity %s session %s active %s name %q",
			userID, identityUserID, sessionUserID, activeAccountID, name)
	}
	var users, memberships int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_user WHERE legacy_tenant_id=$1`, legacyID).Scan(&users); err != nil {
		t.Fatalf("count reconciled users: %v", err)
	}
	if err := st.DB().QueryRowContext(ctx, `
		SELECT count(*) FROM devradar_account_member
		WHERE account_id=$1 AND user_id=$2 AND role='admin' AND revoked_at IS NULL`,
		legacyID, userID).Scan(&memberships); err != nil {
		t.Fatalf("count reconciled memberships: %v", err)
	}
	if users != 1 || memberships != 1 {
		t.Fatalf("idempotent reconcile users=%d memberships=%d, want 1/1", users, memberships)
	}

	otherID := seedLegacyTenantIdentityAndSession(t, st)
	if err := st.ReconcileLegacyAccounts(ctx); err != nil {
		t.Fatalf("reconcile all legacy accounts: %v", err)
	}
	var otherMappings int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_user WHERE legacy_tenant_id=$1`, otherID).Scan(&otherMappings); err != nil {
		t.Fatalf("count bulk reconciled mappings: %v", err)
	}
	if otherMappings != 1 {
		t.Fatalf("bulk reconciled mappings = %d, want 1", otherMappings)
	}
	if err := st.ReconcileLegacyAccounts(ctx); err != nil {
		t.Fatalf("reconcile all legacy accounts again: %v", err)
	}
}

func TestAccountStoreReconcileLegacyAccountsRepairsOnlyNullCompatibilityRows(t *testing.T) {
	st := isolatedStoreAtVersion(t, 29)
	accountID := seedLegacyTenantIdentityAndSession(t, st)
	otherAccountID := seedLegacyTenantIdentityAndSession(t, st)
	applyMigrationFile(t, st, "sql/migrations/030_account_identity.sql")
	ctx := context.Background()

	var legacyUserID string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT id FROM devradar_user WHERE legacy_tenant_id=$1`, accountID).Scan(&legacyUserID); err != nil {
		t.Fatalf("find legacy user: %v", err)
	}
	var memberUserID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_user (email) VALUES ($1) RETURNING id`,
		"member-"+randID(t)[:8]+"@example.com").Scan(&memberUserID); err != nil {
		t.Fatalf("seed member user: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_account_member (account_id,user_id,role)
		VALUES ($1,$2,'reader')`, accountID, memberUserID); err != nil {
		t.Fatalf("seed shared membership: %v", err)
	}
	var memberRevokedAt time.Time
	if err := st.DB().QueryRowContext(ctx, `
		UPDATE devradar_account_member
		SET revoked_at=now(),updated_at=now()
		WHERE account_id=$1 AND user_id=$2
		RETURNING revoked_at`, accountID, memberUserID).Scan(&memberRevokedAt); err != nil {
		t.Fatalf("revoke shared membership: %v", err)
	}
	var unrelatedUserID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_user (email) VALUES ($1) RETURNING id`,
		"unrelated-"+randID(t)[:8]+"@example.com").Scan(&unrelatedUserID); err != nil {
		t.Fatalf("seed unrelated user: %v", err)
	}

	lateIdentitySubject := randID(t)
	nonMemberIdentitySubject := randID(t)
	revokedIdentitySubject := randID(t)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_identity (tenant_id,user_id,provider,subject,email)
		VALUES
			($1,NULL,'github',$2,'late@example.com'),
			($1,$3,'github',$4,'wrong@example.com'),
			($1,$5,'github',$6,'member@example.com')`,
		accountID, lateIdentitySubject, unrelatedUserID, nonMemberIdentitySubject,
		memberUserID, revokedIdentitySubject); err != nil {
		t.Fatalf("seed late compatibility identities: %v", err)
	}
	lateSessionID := randID(t)
	nonMemberSessionID := randID(t)
	revokedSessionID := randID(t)
	expiredSessionID := randID(t)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_session
			(id,tenant_id,user_id,active_account_id,expires_at)
		VALUES
			($1,$2,NULL,NULL,now()+interval '1 hour'),
			($3,$2,$4,$5,now()+interval '1 hour'),
			($6,$2,$7,$2,now()+interval '1 hour'),
			($8,$2,NULL,NULL,now()-interval '1 hour')`,
		lateSessionID, accountID, nonMemberSessionID, unrelatedUserID, otherAccountID,
		revokedSessionID, memberUserID, expiredSessionID); err != nil {
		t.Fatalf("seed late compatibility sessions: %v", err)
	}
	if err := st.ReconcileLegacyAccounts(ctx); err != nil {
		t.Fatalf("reconcile late compatibility rows: %v", err)
	}

	for subject, wantUserID := range map[string]string{
		lateIdentitySubject:      legacyUserID,
		nonMemberIdentitySubject: unrelatedUserID,
		revokedIdentitySubject:   memberUserID,
	} {
		var gotUserID string
		if err := st.DB().QueryRowContext(ctx,
			`SELECT user_id FROM devradar_identity WHERE provider='github' AND subject=$1`, subject).
			Scan(&gotUserID); err != nil {
			t.Fatalf("read reconciled identity %s: %v", subject, err)
		}
		if gotUserID != wantUserID {
			t.Fatalf("identity %s user = %s, want %s", subject, gotUserID, wantUserID)
		}
	}
	for sessionID, want := range map[string]struct {
		userID, activeAccountID string
	}{
		lateSessionID:      {legacyUserID, accountID},
		nonMemberSessionID: {unrelatedUserID, otherAccountID},
		revokedSessionID:   {memberUserID, accountID},
	} {
		var gotUserID, gotAccountID string
		if err := st.DB().QueryRowContext(ctx, `
			SELECT user_id,active_account_id FROM devradar_session WHERE id=$1`, sessionID).
			Scan(&gotUserID, &gotAccountID); err != nil {
			t.Fatalf("read reconciled session %s: %v", sessionID, err)
		}
		if gotUserID != want.userID || gotAccountID != want.activeAccountID {
			t.Fatalf("session %s = user %s account %s, want %s/%s",
				sessionID, gotUserID, gotAccountID, want.userID, want.activeAccountID)
		}
	}
	var expiredUserID, expiredAccountID sql.NullString
	if err := st.DB().QueryRowContext(ctx, `
		SELECT user_id,active_account_id FROM devradar_session WHERE id=$1`, expiredSessionID).
		Scan(&expiredUserID, &expiredAccountID); err != nil {
		t.Fatalf("read expired compatibility session: %v", err)
	}
	if expiredUserID.Valid || expiredAccountID.Valid {
		t.Fatalf("expired session was reconciled: user=%v account=%v", expiredUserID, expiredAccountID)
	}

	var role string
	var revokedAt time.Time
	if err := st.DB().QueryRowContext(ctx, `
		SELECT role,revoked_at FROM devradar_account_member
		WHERE account_id=$1 AND user_id=$2`, accountID, memberUserID).
		Scan(&role, &revokedAt); err != nil {
		t.Fatalf("read preserved revoked membership: %v", err)
	}
	if role != "reader" || !revokedAt.Equal(memberRevokedAt) {
		t.Fatalf("revoked membership = role %s revoked %s, want reader/%s",
			role, revokedAt, memberRevokedAt)
	}
	var unrelatedMemberships int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT count(*) FROM devradar_account_member
		WHERE account_id=$1 AND user_id=$2`, accountID, unrelatedUserID).
		Scan(&unrelatedMemberships); err != nil {
		t.Fatalf("count unrelated memberships: %v", err)
	}
	if unrelatedMemberships != 0 {
		t.Fatalf("unrelated user gained %d memberships", unrelatedMemberships)
	}
}

func TestAccountStoreReconcileLegacyAccountsPreservesLegacyMembershipState(t *testing.T) {
	st := isolatedStoreAtVersion(t, 29)
	editorAccountID := seedLegacyTenantIdentityAndSession(t, st)
	revokedAccountID := seedLegacyTenantIdentityAndSession(t, st)
	missingAccountID := seedLegacyTenantIdentityAndSession(t, st)
	applyMigrationFile(t, st, "sql/migrations/030_account_identity.sql")
	ctx := context.Background()

	var editorUserID, revokedUserID, missingUserID string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT id FROM devradar_user WHERE legacy_tenant_id=$1`, editorAccountID).
		Scan(&editorUserID); err != nil {
		t.Fatalf("find editor legacy user: %v", err)
	}
	if err := st.DB().QueryRowContext(ctx,
		`SELECT id FROM devradar_user WHERE legacy_tenant_id=$1`, revokedAccountID).
		Scan(&revokedUserID); err != nil {
		t.Fatalf("find revoked legacy user: %v", err)
	}
	if err := st.DB().QueryRowContext(ctx,
		`SELECT id FROM devradar_user WHERE legacy_tenant_id=$1`, missingAccountID).
		Scan(&missingUserID); err != nil {
		t.Fatalf("find missing-membership legacy user: %v", err)
	}
	editorUpdatedAt := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Microsecond)
	revokedAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	if _, err := st.DB().ExecContext(ctx, `
		UPDATE devradar_account_member
		SET role='editor',updated_at=$3
		WHERE account_id=$1 AND user_id=$2`, editorAccountID, editorUserID, editorUpdatedAt); err != nil {
		t.Fatalf("demote legacy membership: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		UPDATE devradar_account_member
		SET revoked_at=$3,updated_at=$3
		WHERE account_id=$1 AND user_id=$2`, revokedAccountID, revokedUserID, revokedAt); err != nil {
		t.Fatalf("revoke legacy membership: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		DELETE FROM devradar_account_member WHERE account_id=$1 AND user_id=$2`,
		missingAccountID, missingUserID); err != nil {
		t.Fatalf("delete legacy membership: %v", err)
	}

	if err := st.ReconcileLegacyAccounts(ctx); err != nil {
		t.Fatalf("reconcile authoritative membership states: %v", err)
	}

	var editorRole string
	var gotEditorUpdatedAt time.Time
	if err := st.DB().QueryRowContext(ctx, `
		SELECT role,updated_at FROM devradar_account_member
		WHERE account_id=$1 AND user_id=$2`, editorAccountID, editorUserID).
		Scan(&editorRole, &gotEditorUpdatedAt); err != nil {
		t.Fatalf("read editor membership: %v", err)
	}
	if editorRole != "editor" || !gotEditorUpdatedAt.Equal(editorUpdatedAt) {
		t.Fatalf("editor membership = %s/%s, want editor/%s",
			editorRole, gotEditorUpdatedAt, editorUpdatedAt)
	}
	var gotRevokedAt, gotRevokedUpdatedAt time.Time
	if err := st.DB().QueryRowContext(ctx, `
		SELECT revoked_at,updated_at FROM devradar_account_member
		WHERE account_id=$1 AND user_id=$2`, revokedAccountID, revokedUserID).
		Scan(&gotRevokedAt, &gotRevokedUpdatedAt); err != nil {
		t.Fatalf("read revoked membership: %v", err)
	}
	if !gotRevokedAt.Equal(revokedAt) || !gotRevokedUpdatedAt.Equal(revokedAt) {
		t.Fatalf("revoked membership = %s/%s, want %s", gotRevokedAt, gotRevokedUpdatedAt, revokedAt)
	}
	var missingRole string
	if err := st.DB().QueryRowContext(ctx, `
		SELECT role FROM devradar_account_member
		WHERE account_id=$1 AND user_id=$2`, missingAccountID, missingUserID).
		Scan(&missingRole); err != nil {
		t.Fatalf("read restored missing membership: %v", err)
	}
	if missingRole != "admin" {
		t.Fatalf("restored missing membership role = %s, want admin", missingRole)
	}
}

func seedLegacyTenantIdentityAndSession(t *testing.T, st *postgres.Store) string {
	t.Helper()
	ctx := context.Background()
	email := "legacy-" + randID(t)[:8] + "@example.com"
	var accountID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_tenant (email,email_verified_at,avatar_url,tos_accepted_at)
		VALUES ($1,now(),$2,now()) RETURNING id`, email, "https://example.com/avatar").Scan(&accountID); err != nil {
		t.Fatalf("seed legacy tenant: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_identity (tenant_id,provider,subject,email)
		VALUES ($1,'magiclink',$2,$2)`, accountID, email); err != nil {
		t.Fatalf("seed legacy identity: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_session (id,tenant_id,expires_at)
		VALUES ($1,$2,now()+interval '1 hour')`, randID(t), accountID); err != nil {
		t.Fatalf("seed legacy session: %v", err)
	}
	return accountID
}

func applyMigrationFile(t *testing.T, st *postgres.Store, path string) {
	t.Helper()
	ddl, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migration %s: %v", path, err)
	}
	tx, err := st.DB().BeginTx(context.Background(), &sql.TxOptions{})
	if err != nil {
		t.Fatalf("begin migration %s: %v", path, err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(string(ddl)); err != nil {
		t.Fatalf("apply migration %s: %v", path, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit migration %s: %v", path, err)
	}
}

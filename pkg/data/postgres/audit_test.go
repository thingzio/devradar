package postgres_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/attest"
	"github.com/thingzio/devradar/pkg/authn"
	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/vex"
)

func TestAccountStateAuditMigration(t *testing.T) {
	st := isolatedStoreAtVersion(t, 30)
	ctx := context.Background()

	var accountID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_tenant (email,name)
		VALUES ($1,$2) RETURNING id`,
		"audit-migration-"+randID(t)[:8]+"@example.com", "Audit migration").Scan(&accountID); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if err := st.ReconcileLegacyAccount(ctx, accountID); err != nil {
		t.Fatalf("reconcile account: %v", err)
	}
	var userID string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT id FROM devradar_user WHERE legacy_tenant_id=$1`, accountID).Scan(&userID); err != nil {
		t.Fatalf("read migrated user: %v", err)
	}

	sb := seedTenantAndSBOMForAccount(t, st, accountID)
	policy, err := st.EnsureAlertPolicy(ctx, accountID)
	if err != nil {
		t.Fatalf("ensure policy: %v", err)
	}
	readAlertID := seedMigrationAlert(t, st, accountID, policy.ID, sb.ID, true)
	unreadAlertID := seedMigrationAlert(t, st, accountID, policy.ID, sb.ID, false)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_token_flash (tenant_id,value,expires_at)
		VALUES ($1,'legacy-secret',now()+interval '2 minutes')`, accountID); err != nil {
		t.Fatalf("seed legacy flash: %v", err)
	}
	sessionID := randID(t)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_session (id,tenant_id,user_id,active_account_id,expires_at)
		VALUES ($1,$2,$3,$2,now()+interval '1 hour')`, sessionID, accountID, userID); err != nil {
		t.Fatalf("seed session flash owner: %v", err)
	}
	var actorTokenID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_api_token (tenant_id,name,token_hash)
		VALUES ($1,'migration actor',$2) RETURNING id`, accountID, randID(t)).Scan(&actorTokenID); err != nil {
		t.Fatalf("seed migration actor token: %v", err)
	}

	applyMigrationFile(t, st, "sql/migrations/031_account_state_audit.sql")
	applyMigrationFile(t, st, "sql/migrations/031_account_state_audit.sql")

	for _, table := range []string{
		"devradar_audit_event", "devradar_alert_receipt", "devradar_session_token_flash",
	} {
		var exists bool
		if err := st.DB().QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.tables
				WHERE table_schema=current_schema() AND table_name=$1
			)`, table).Scan(&exists); err != nil {
			t.Fatalf("check table %s: %v", table, err)
		}
		if !exists {
			t.Errorf("table %s was not created", table)
		}
	}

	var receiptCount int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT count(*) FROM devradar_alert_receipt
		WHERE account_id=$1 AND user_id=$2 AND alert_id=$3`,
		accountID, userID, readAlertID).Scan(&receiptCount); err != nil {
		t.Fatalf("count read receipt: %v", err)
	}
	if receiptCount != 1 {
		t.Fatalf("globally read alert receipts = %d, want 1", receiptCount)
	}
	if err := st.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_alert_receipt WHERE alert_id=$1`, unreadAlertID).
		Scan(&receiptCount); err != nil {
		t.Fatalf("count unread receipt: %v", err)
	}
	if receiptCount != 0 {
		t.Fatalf("globally unread alert receipts = %d, want 0", receiptCount)
	}

	var legacyFlashCount int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_token_flash WHERE tenant_id=$1`, accountID).
		Scan(&legacyFlashCount); err != nil {
		t.Fatalf("count legacy flash: %v", err)
	}
	if legacyFlashCount != 1 {
		t.Fatalf("legacy flash rows = %d, want preserved row", legacyFlashCount)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_session_token_flash (session_id,account_id,value,expires_at)
		VALUES ($1,$2,'new-secret',now()+interval '2 minutes')`, sessionID, accountID); err != nil {
		t.Fatalf("insert session/account flash: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_session_token_flash (session_id,account_id,value,expires_at)
		VALUES ($1,$2,'duplicate',now()+interval '2 minutes')`, sessionID, accountID); err == nil {
		t.Fatal("duplicate session/account flash key was accepted")
	}

	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_audit_event
			(account_id,actor_kind,actor_user_id,action,target_type,target_id,outcome,request_id,metadata)
		VALUES ($1,'user',$2,$3,'account',$1,'success','request-id','{}')`,
		accountID, userID, strings.Repeat("a", 97)); err == nil {
		t.Fatal("audit action longer than 96 characters was accepted")
	}
	_, actorShapeErr := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_audit_event
			(account_id,actor_kind,actor_user_id,actor_api_token_id,
			 action,target_type,target_id,outcome,request_id)
		VALUES ($1::uuid,'user',$2,$3,'test.actor_shape','account',$1::text,'success','request-id')`,
		accountID, userID, actorTokenID)
	if actorShapeErr == nil {
		t.Fatal("user audit actor with an API-token reference was accepted")
	}
	var actorShapePQ *pq.Error
	if !errors.As(actorShapeErr, &actorShapePQ) || actorShapePQ.Constraint != "devradar_audit_event_actor_shape" {
		t.Fatalf("actor shape rejection = %v, want devradar_audit_event_actor_shape", actorShapeErr)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_audit_event
			(account_id,actor_kind,actor_user_id,action,target_type,target_id,outcome,request_id,metadata)
		VALUES ($1,'user',$2,'test','account',$1,'success','request-id',$3::jsonb)`,
		accountID, userID, `{"value":"`+strings.Repeat("x", 4097)+`"}`); err == nil {
		t.Fatal("audit metadata larger than 4096 bytes was accepted")
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_audit_event
			(account_id,actor_kind,actor_user_id,action,target_type,target_id,outcome,request_id)
		VALUES ($1::uuid,'user',$2,'test.delete','account',$1::text,'success','request-id')`,
		accountID, userID); err != nil {
		t.Fatalf("seed account deletion audit: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `DELETE FROM devradar_tenant WHERE id=$1`, accountID); err != nil {
		t.Fatalf("hard-delete account with audit rows: %v", err)
	}
	var auditAfterDelete int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_audit_event WHERE account_id=$1`, accountID).
		Scan(&auditAfterDelete); err != nil {
		t.Fatalf("count account audit after delete: %v", err)
	}
	if auditAfterDelete != 0 {
		t.Fatalf("account audit rows after hard delete = %d, want cascade", auditAfterDelete)
	}
}

func TestWithAuditActorAttributionAndFKNulling(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, userID := seedAuditAccount(t, st)
	var tokenID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_api_token (tenant_id,name,token_hash,created_by_user_id)
		VALUES ($1,'audit actor',$2,$3) RETURNING id`, accountID, randID(t), userID).
		Scan(&tokenID); err != nil {
		t.Fatalf("seed api token actor: %v", err)
	}

	actors := []account.Actor{
		{Kind: account.ActorUser, UserID: userID},
		{Kind: account.ActorAPIToken, APITokenID: tokenID},
		{Kind: account.ActorPlatform, UserID: userID},
	}
	for _, actor := range actors {
		event := postgres.AuditEvent{
			Action: "test.actor", TargetType: "account", TargetID: accountID,
			Outcome: "success", RequestID: randID(t), Metadata: map[string]string{"source": "test"},
		}
		if err := st.WithAudit(ctx, accountID, actor, event, func(*sql.Tx) error { return nil }); err != nil {
			t.Fatalf("audit actor %s: %v", actor.Kind, err)
		}
	}

	rows, err := st.DB().QueryContext(ctx, `
		SELECT actor_kind,actor_user_id::text,actor_api_token_id::text,metadata::text
		FROM devradar_audit_event WHERE account_id=$1 ORDER BY id`, accountID)
	if err != nil {
		t.Fatalf("read actors: %v", err)
	}
	defer func() { _ = rows.Close() }()
	want := []struct{ kind, user, token string }{
		{"user", userID, ""}, {"api_token", "", tokenID}, {"platform", userID, ""},
	}
	for i := 0; rows.Next(); i++ {
		if i >= len(want) {
			t.Fatal("more audit actors than expected")
		}
		var kind string
		var gotUser, gotToken sql.NullString
		var metadata string
		if err := rows.Scan(&kind, &gotUser, &gotToken, &metadata); err != nil {
			t.Fatalf("scan actor: %v", err)
		}
		if kind != want[i].kind || gotUser.String != want[i].user || gotToken.String != want[i].token {
			t.Fatalf("actor %d = %s/%s/%s, want %s/%s/%s", i, kind, gotUser.String,
				gotToken.String, want[i].kind, want[i].user, want[i].token)
		}
		if strings.Contains(metadata, tokenID) {
			t.Fatal("audit metadata contains credential actor identifier")
		}
	}

	if _, err := st.DB().ExecContext(ctx, `DELETE FROM devradar_api_token WHERE id=$1`, tokenID); err != nil {
		t.Fatalf("delete actor token: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `DELETE FROM devradar_user WHERE id=$1`, userID); err != nil {
		t.Fatalf("delete actor user: %v", err)
	}
	var dangling int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT count(*) FROM devradar_audit_event
		WHERE account_id=$1 AND (actor_user_id IS NOT NULL OR actor_api_token_id IS NOT NULL)`,
		accountID).Scan(&dangling); err != nil {
		t.Fatalf("count dangling actor references: %v", err)
	}
	if dangling != 0 {
		t.Fatalf("dangling actor references = %d, want 0 after SET NULL", dangling)
	}
}

func TestAuditEventRejectsDirectUpdateAndDelete(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, userID := seedAuditAccount(t, st)
	seedEvent := func(action string) int64 {
		t.Helper()
		var id int64
		if err := st.DB().QueryRowContext(ctx, `
			INSERT INTO devradar_audit_event
				(account_id,actor_kind,actor_user_id,action,target_type,target_id,outcome,request_id)
			VALUES ($1::uuid,'user',$2,$3,'account',$1::text,'success',$4)
			RETURNING id`, accountID, userID, action, randID(t)).Scan(&id); err != nil {
			t.Fatalf("insert audit event: %v", err)
		}
		return id
	}

	for _, tc := range []struct {
		name  string
		query string
		id    int64
	}{
		{"update payload", `UPDATE devradar_audit_event SET outcome='tampered' WHERE id=$1`, seedEvent("test.append.update")},
		{"null actor directly", `UPDATE devradar_audit_event SET actor_user_id=NULL WHERE id=$1`, seedEvent("test.append.actor")},
		{"delete", `DELETE FROM devradar_audit_event WHERE id=$1`, seedEvent("test.append.delete")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := st.DB().ExecContext(ctx, tc.query, tc.id); err == nil {
				t.Fatal("direct audit mutation was accepted")
			}
			var exists bool
			if err := st.DB().QueryRowContext(ctx,
				`SELECT EXISTS(SELECT 1 FROM devradar_audit_event WHERE id=$1)`, tc.id).Scan(&exists); err != nil {
				t.Fatalf("check protected audit event: %v", err)
			}
			if !exists {
				t.Fatal("protected audit event was removed")
			}
		})
	}
}

func TestWithAuditInsertionFailureRollsBackMutation(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, userID := seedAuditAccount(t, st)
	if _, err := st.DB().ExecContext(ctx, `
		ALTER TABLE devradar_audit_event ADD CONSTRAINT test_reject_forced_audit
		CHECK (action <> 'forced.failure')`); err != nil {
		t.Fatalf("add forced audit failure: %v", err)
	}

	err := st.WithAudit(ctx, accountID, account.Actor{Kind: account.ActorUser, UserID: userID},
		postgres.AuditEvent{
			Action: "forced.failure", TargetType: "account", TargetID: accountID,
			Outcome: "success", RequestID: randID(t),
		}, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx,
				`UPDATE devradar_tenant SET name='must roll back' WHERE id=$1`, accountID)
			return err
		})
	if err == nil {
		t.Fatal("forced audit insertion failure returned nil")
	}
	var name string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT name FROM devradar_tenant WHERE id=$1`, accountID).Scan(&name); err != nil {
		t.Fatalf("read account after rollback: %v", err)
	}
	if name == "must roll back" {
		t.Fatal("protected account mutation committed without its audit event")
	}
}

func TestWithAuditRejectsSecretMetadataBeforeMutation(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	accountID, userID := seedAuditAccount(t, st)
	mutated := false
	err := st.WithAudit(context.Background(), accountID,
		account.Actor{Kind: account.ActorUser, UserID: userID}, postgres.AuditEvent{
			Action: "test.secret", TargetType: "account", TargetID: accountID,
			Outcome: "success", RequestID: randID(t),
			Metadata: map[string]string{"api_token": "dr_raw-secret"},
		}, func(*sql.Tx) error {
			mutated = true
			return nil
		})
	if err == nil {
		t.Fatal("secret-bearing audit metadata was accepted")
	}
	if mutated {
		t.Fatal("mutation ran before audit metadata validation")
	}
}

func TestWithAuditRejectsForeignAccountActorBeforeMutation(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	targetAccountID, _ := seedAuditAccount(t, st)
	foreignAccountID, foreignUserID := seedAuditAccount(t, st)
	foreignTokenID := seedAuditAPIToken(t, st, foreignAccountID)
	for _, actor := range []account.Actor{
		{Kind: account.ActorUser, UserID: foreignUserID},
		{Kind: account.ActorAPIToken, APITokenID: foreignTokenID},
	} {
		mutated := false
		err := st.WithAudit(ctx, targetAccountID, actor, postgres.AuditEvent{
			Action: "test.foreign_actor", TargetType: "account", TargetID: targetAccountID,
			Outcome: "success", RequestID: randID(t),
		}, func(*sql.Tx) error {
			mutated = true
			return nil
		})
		if err == nil {
			t.Fatalf("foreign %s actor was accepted", actor.Kind)
		}
		if mutated {
			t.Fatalf("mutation ran for foreign %s actor", actor.Kind)
		}
	}
}

func seedAuditAccount(t *testing.T, st *postgres.Store) (accountID, userID string) {
	t.Helper()
	ctx := context.Background()
	email := "audit-" + randID(t)[:8] + "@example.com"
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_tenant (email,name) VALUES ($1,'Original') RETURNING id`, email).
		Scan(&accountID); err != nil {
		t.Fatalf("seed audit account: %v", err)
	}
	if err := st.ReconcileLegacyAccount(ctx, accountID); err != nil {
		t.Fatalf("reconcile audit account: %v", err)
	}
	if err := st.DB().QueryRowContext(ctx,
		`SELECT id FROM devradar_user WHERE legacy_tenant_id=$1`, accountID).Scan(&userID); err != nil {
		t.Fatalf("read audit user: %v", err)
	}
	return accountID, userID
}

func TestAuditedAccountPolicyMutations(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, userID := seedAuditAccount(t, st)
	actor := account.Actor{Kind: account.ActorUser, UserID: userID}
	requestID := randID(t)
	if _, err := st.EnsureAlertPolicy(ctx, accountID); err != nil {
		t.Fatalf("ensure alert policy: %v", err)
	}

	if err := st.UpdateAccountNameAudited(ctx, accountID, "Renamed", actor, requestID); err != nil {
		t.Fatalf("update account name: %v", err)
	}
	if err := st.SetMinSeverityAudited(ctx, accountID, "high", actor, requestID); err != nil {
		t.Fatalf("set minimum severity: %v", err)
	}
	if err := st.UpdateAlertPolicyAudited(ctx, accountID, postgres.AlertPolicy{
		Enabled: true, MinSeverity: "high", AlertKEV: true, AlertFixAvailable: true,
		IncludeImage: true, IncludeDB: true,
	}, actor, requestID); err != nil {
		t.Fatalf("update alert policy: %v", err)
	}
	if err := st.SetLicensePolicyAudited(ctx, accountID, data.LicensePolicy{
		DeniedCategories: []data.LicenseCategory{data.CategoryStrongCopyleft},
	}, actor, requestID); err != nil {
		t.Fatalf("set license policy: %v", err)
	}

	var actions []string
	rows, err := st.DB().QueryContext(ctx, `
		SELECT action FROM devradar_audit_event
		WHERE account_id=$1 ORDER BY id`, accountID)
	if err != nil {
		t.Fatalf("list policy audit actions: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var action string
		if err := rows.Scan(&action); err != nil {
			t.Fatalf("scan policy action: %v", err)
		}
		actions = append(actions, action)
	}
	want := []string{
		"account.name.update", "account.min_severity.update",
		"account.alert_policy.update", "account.license_policy.update",
	}
	if strings.Join(actions, ",") != strings.Join(want, ",") {
		t.Fatalf("policy audit actions = %v, want %v", actions, want)
	}

	// An idempotent retry changes no row and appends no duplicate event.
	if err := st.SetMinSeverityAudited(ctx, accountID, "high", actor, randID(t)); err != nil {
		t.Fatalf("repeat minimum severity: %v", err)
	}
	var count int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT count(*) FROM devradar_audit_event
		WHERE account_id=$1 AND action='account.min_severity.update'`, accountID).Scan(&count); err != nil {
		t.Fatalf("count minimum severity audit: %v", err)
	}
	if count != 1 {
		t.Fatalf("minimum severity audit count = %d, want 1 after no-op retry", count)
	}
}

func TestUpdateAccountNameAuditedRejectsInvalidNamesBeforeMutation(t *testing.T) {
	for _, name := range []string{
		"", "   ", " leading", "trailing ", strings.Repeat("界", 81),
	} {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			st := isolatedAdminProductHealthStore(t)
			ctx := context.Background()
			accountID, userID := seedAuditAccount(t, st)
			err := st.UpdateAccountNameAudited(ctx, accountID, name,
				account.Actor{Kind: account.ActorUser, UserID: userID}, randID(t))
			if err == nil {
				t.Fatalf("invalid account name %q was accepted", name)
			}
			var stored string
			var audits int
			if err := st.DB().QueryRowContext(ctx, `
				SELECT name,
				       (SELECT count(*) FROM devradar_audit_event
				        WHERE account_id=$1 AND action='account.name.update')
				FROM devradar_tenant WHERE id=$1`, accountID).Scan(&stored, &audits); err != nil {
				t.Fatalf("read rejected account name: %v", err)
			}
			if stored != "Original" || audits != 0 {
				t.Fatalf("rejected account name changed state/audit = %q/%d", stored, audits)
			}
		})
	}
}

func TestUpdateAccountNameAuditedAllowsUnicodeLimitAndDuplicates(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	firstAccountID, firstUserID := seedAuditAccount(t, st)
	secondAccountID, secondUserID := seedAuditAccount(t, st)
	name := strings.Repeat("界", 80)
	for _, tc := range []struct{ accountID, userID string }{
		{firstAccountID, firstUserID}, {secondAccountID, secondUserID},
	} {
		if err := st.UpdateAccountNameAudited(ctx, tc.accountID, name,
			account.Actor{Kind: account.ActorUser, UserID: tc.userID}, randID(t)); err != nil {
			t.Fatalf("set duplicate Unicode account name: %v", err)
		}
	}
}

func TestAuditedAccountPolicyAuditFailureRollsBack(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, userID := seedAuditAccount(t, st)
	if _, err := st.DB().ExecContext(ctx, `
		ALTER TABLE devradar_audit_event ADD CONSTRAINT test_reject_account_policy
		CHECK (action <> 'account.min_severity.update')`); err != nil {
		t.Fatalf("add policy audit failure: %v", err)
	}
	err := st.SetMinSeverityAudited(ctx, accountID, "critical",
		account.Actor{Kind: account.ActorUser, UserID: userID}, randID(t))
	if err == nil {
		t.Fatal("policy audit failure returned nil")
	}
	var severity string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT min_severity FROM devradar_tenant WHERE id=$1`, accountID).Scan(&severity); err != nil {
		t.Fatalf("read rolled back policy: %v", err)
	}
	if severity != "medium" {
		t.Fatalf("minimum severity = %q, want original medium after rollback", severity)
	}
}

func TestAuditedAPITokenCreateAndRevoke(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, userID := seedAuditAccount(t, st)
	actor := account.Actor{Kind: account.ActorUser, UserID: userID}
	session, err := st.CreateSession(ctx, userID, &accountID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAPIToken(ctx, accountID, userID, authn.HashToken(session),
		"ci", time.Hour, 10, randID(t), bytes.Repeat([]byte{4}, 32)); err != nil {
		t.Fatalf("create audited api token: %v", err)
	}
	raw, err := st.ConsumeTokenFlash(ctx, authn.HashToken(session), accountID, bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, "dr_") {
		t.Fatalf("raw token prefix = %q", raw)
	}
	var tokenID, creatorID string
	if err := st.DB().QueryRowContext(ctx, `
		SELECT id,created_by_user_id FROM devradar_api_token
		WHERE tenant_id=$1 AND name='ci'`, accountID).Scan(&tokenID, &creatorID); err != nil {
		t.Fatalf("read created token: %v", err)
	}
	if creatorID != userID {
		t.Fatalf("token creator = %s, want actor user %s", creatorID, userID)
	}
	var action, targetType, targetID, metadata string
	if err := st.DB().QueryRowContext(ctx, `
		SELECT action,target_type,target_id,metadata::text
		FROM devradar_audit_event WHERE account_id=$1 ORDER BY id DESC LIMIT 1`, accountID).
		Scan(&action, &targetType, &targetID, &metadata); err != nil {
		t.Fatalf("read create token audit: %v", err)
	}
	if action != "api_token.create" || targetType != "api_token" || targetID != tokenID {
		t.Fatalf("create token audit = %s/%s/%s, want api_token.create/api_token/%s",
			action, targetType, targetID, tokenID)
	}
	if strings.Contains(metadata, raw) || strings.Contains(metadata, "dr_") {
		t.Fatal("raw API token leaked into audit metadata")
	}

	if err := st.RevokeAPIToken(ctx, accountID, tokenID, actor, randID(t)); err != nil {
		t.Fatalf("revoke audited api token: %v", err)
	}
	if err := st.DB().QueryRowContext(ctx, `
		SELECT action,target_type,target_id FROM devradar_audit_event
		WHERE account_id=$1 ORDER BY id DESC LIMIT 1`, accountID).
		Scan(&action, &targetType, &targetID); err != nil {
		t.Fatalf("read revoke token audit: %v", err)
	}
	if action != "api_token.revoke" || targetType != "api_token" || targetID != tokenID {
		t.Fatalf("revoke token audit = %s/%s/%s", action, targetType, targetID)
	}
}

func TestAuditedAPITokenAuditFailuresRollBack(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		st := isolatedAdminProductHealthStore(t)
		ctx := context.Background()
		accountID, userID := seedAuditAccount(t, st)
		session, err := st.CreateSession(ctx, userID, &accountID, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := st.DB().ExecContext(ctx, `
			ALTER TABLE devradar_audit_event ADD CONSTRAINT test_reject_token_create
			CHECK (action <> 'api_token.create')`); err != nil {
			t.Fatalf("add token create audit failure: %v", err)
		}
		if _, err := st.CreateAPIToken(ctx, accountID, userID, authn.HashToken(session),
			"rollback", 0, 10, randID(t), bytes.Repeat([]byte{5}, 32)); err == nil {
			t.Fatal("token create audit failure returned nil")
		}
		var count int
		if err := st.DB().QueryRowContext(ctx,
			`SELECT count(*) FROM devradar_api_token WHERE tenant_id=$1`, accountID).Scan(&count); err != nil {
			t.Fatalf("count rolled back tokens: %v", err)
		}
		if count != 0 {
			t.Fatalf("tokens after audit failure = %d, want 0", count)
		}
	})

	t.Run("revoke", func(t *testing.T) {
		st := isolatedAdminProductHealthStore(t)
		ctx := context.Background()
		accountID, userID := seedAuditAccount(t, st)
		var tokenID string
		if err := st.DB().QueryRowContext(ctx, `
			INSERT INTO devradar_api_token (tenant_id,name,token_hash)
			VALUES ($1,'keep',$2) RETURNING id`, accountID, randID(t)).Scan(&tokenID); err != nil {
			t.Fatalf("seed revoke token: %v", err)
		}
		if _, err := st.DB().ExecContext(ctx, `
			ALTER TABLE devradar_audit_event ADD CONSTRAINT test_reject_token_revoke
			CHECK (action <> 'api_token.revoke')`); err != nil {
			t.Fatalf("add token revoke audit failure: %v", err)
		}
		if err := st.RevokeAPIToken(ctx, accountID, tokenID,
			account.Actor{Kind: account.ActorUser, UserID: userID}, randID(t)); err == nil {
			t.Fatal("token revoke audit failure returned nil")
		}
		var exists bool
		if err := st.DB().QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM devradar_api_token WHERE id=$1)`, tokenID).Scan(&exists); err != nil {
			t.Fatalf("check rolled back token: %v", err)
		}
		if !exists {
			t.Fatal("token revoke committed without its audit event")
		}
	})
}

func TestAuditedVEXSaveAndRollback(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		st := isolatedAdminProductHealthStore(t)
		ctx := context.Background()
		accountID, userID := seedAuditAccount(t, st)
		doc := &vex.Document{Author: "security@example.com", Raw: []byte(`{"secret":"must-not-copy"}`)}
		id, _, err := st.SaveVEXDocumentAudited(ctx, accountID, doc,
			account.Actor{Kind: account.ActorUser, UserID: userID}, randID(t))
		if err != nil {
			t.Fatalf("save audited VEX: %v", err)
		}
		var action, targetType, targetID, metadata string
		if err := st.DB().QueryRowContext(ctx, `
			SELECT action,target_type,target_id,metadata::text
			FROM devradar_audit_event WHERE account_id=$1`, accountID).
			Scan(&action, &targetType, &targetID, &metadata); err != nil {
			t.Fatalf("read VEX audit: %v", err)
		}
		if action != "vex.save" || targetType != "vex_document" || targetID != id {
			t.Fatalf("VEX audit = %s/%s/%s, want vex.save/vex_document/%s",
				action, targetType, targetID, id)
		}
		if strings.Contains(metadata, "must-not-copy") || strings.Contains(metadata, "security@example.com") {
			t.Fatal("raw VEX content leaked into audit metadata")
		}
	})

	t.Run("audit failure", func(t *testing.T) {
		st := isolatedAdminProductHealthStore(t)
		ctx := context.Background()
		accountID, userID := seedAuditAccount(t, st)
		if _, err := st.DB().ExecContext(ctx, `
			ALTER TABLE devradar_audit_event ADD CONSTRAINT test_reject_vex
			CHECK (action <> 'vex.save')`); err != nil {
			t.Fatalf("add VEX audit failure: %v", err)
		}
		if _, _, err := st.SaveVEXDocumentAudited(ctx, accountID,
			&vex.Document{Raw: []byte(`{}`)},
			account.Actor{Kind: account.ActorUser, UserID: userID}, randID(t)); err == nil {
			t.Fatal("VEX audit failure returned nil")
		}
		var count int
		if err := st.DB().QueryRowContext(ctx,
			`SELECT count(*) FROM devradar_vex_document WHERE tenant_id=$1`, accountID).Scan(&count); err != nil {
			t.Fatalf("count rolled back VEX documents: %v", err)
		}
		if count != 0 {
			t.Fatalf("VEX documents after audit failure = %d, want 0", count)
		}
	})
}

func TestAuditedArchiveMutationsAndNoOpRetries(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, userID := seedAuditAccount(t, st)
	actor := account.Actor{Kind: account.ActorUser, UserID: userID}
	sb := seedTenantAndSBOMForAccount(t, st, accountID)

	if err := st.ArchiveSBOMAudited(ctx, accountID, sb.ID, actor, randID(t)); err != nil {
		t.Fatalf("archive audited SBOM: %v", err)
	}
	if err := st.ArchiveSBOMAudited(ctx, accountID, sb.ID, actor, randID(t)); err != nil {
		t.Fatalf("repeat archive audited SBOM: %v", err)
	}

	first := seedTenantAndSBOMForAccount(t, st, accountID)
	second := seedTenantAndSBOMForAccount(t, st, accountID)
	archived, err := st.ArchiveRepoAudited(ctx, accountID, first.Repository, actor, randID(t))
	if err != nil {
		t.Fatalf("archive audited repository: %v", err)
	}
	if archived != 2 {
		t.Fatalf("archived repository rows = %d, want 2", archived)
	}
	archived, err = st.ArchiveRepoAudited(ctx, accountID, second.Repository, actor, randID(t))
	if err != nil || archived != 0 {
		t.Fatalf("repeat repository archive = %d, %v; want 0, nil", archived, err)
	}

	for action, want := range map[string]int{
		"sbom.archive": 1, "repository.archive": 1,
	} {
		var count int
		if err := st.DB().QueryRowContext(ctx, `
			SELECT count(*) FROM devradar_audit_event WHERE account_id=$1 AND action=$2`,
			accountID, action).Scan(&count); err != nil {
			t.Fatalf("count %s audit: %v", action, err)
		}
		if count != want {
			t.Fatalf("%s audit count = %d, want %d after retry", action, count, want)
		}
	}
}

func TestAuditedArchiveLongRepositoryUsesDeterministicBoundedTarget(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, userID := seedAuditAccount(t, st)
	repository := "registry.test/" + strings.Repeat("界", 513)
	first := seedTenantAndSBOMForAccount(t, st, accountID)
	second := seedTenantAndSBOMForAccount(t, st, accountID)
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_sbom SET repository=$2 WHERE id=ANY($1::text[])`,
		pq.Array([]string{first.ID, second.ID}), repository); err != nil {
		t.Fatalf("seed long repository: %v", err)
	}
	actor := account.Actor{Kind: account.ActorUser, UserID: userID}
	archived, err := st.ArchiveRepoAudited(ctx, accountID, repository, actor, randID(t))
	if err != nil || archived != 2 {
		t.Fatalf("archive long repository = %d, %v; want 2, nil", archived, err)
	}
	sum := sha256.Sum256([]byte(repository))
	wantTarget := "sha256:" + hex.EncodeToString(sum[:])
	var targetID string
	if err := st.DB().QueryRowContext(ctx, `
		SELECT target_id FROM devradar_audit_event
		WHERE account_id=$1 AND action='repository.archive'`, accountID).Scan(&targetID); err != nil {
		t.Fatalf("read long repository audit: %v", err)
	}
	if targetID != wantTarget || len(targetID) != 71 {
		t.Fatalf("long repository audit target = %q, want %q", targetID, wantTarget)
	}
	archived, err = st.ArchiveRepoAudited(ctx, accountID, repository, actor, randID(t))
	if err != nil || archived != 0 {
		t.Fatalf("repeat long repository archive = %d, %v", archived, err)
	}
	var audits int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT count(*) FROM devradar_audit_event
		WHERE account_id=$1 AND action='repository.archive'`, accountID).Scan(&audits); err != nil {
		t.Fatalf("count long repository audits: %v", err)
	}
	if audits != 1 {
		t.Fatalf("long repository audit count = %d, want 1", audits)
	}
}

func TestAuditedArchiveInvalidExactRepositoryUsesDeterministicTarget(t *testing.T) {
	for _, repository := range []string{
		" registry.test/team/leading",
		"registry.test/team/trailing ",
		"",
	} {
		t.Run(fmt.Sprintf("%q", repository), func(t *testing.T) {
			st := isolatedAdminProductHealthStore(t)
			ctx := context.Background()
			accountID, userID := seedAuditAccount(t, st)
			first := seedTenantAndSBOMForAccount(t, st, accountID)
			second := seedTenantAndSBOMForAccount(t, st, accountID)
			other := seedTenantAndSBOMForAccount(t, st, accountID)
			otherRepository := strings.TrimSpace(repository)
			if otherRepository == repository {
				otherRepository = "registry.test/team/not-empty"
			}
			if _, err := st.DB().ExecContext(ctx, `
				UPDATE devradar_sbom
				SET repository=CASE WHEN id=ANY($1::text[]) THEN $2 ELSE $3 END
				WHERE id=ANY($4::text[])`,
				pq.Array([]string{first.ID, second.ID}), repository, otherRepository,
				pq.Array([]string{first.ID, second.ID, other.ID})); err != nil {
				t.Fatalf("seed exact repositories: %v", err)
			}

			actor := account.Actor{Kind: account.ActorUser, UserID: userID}
			archived, err := st.ArchiveRepoAudited(ctx, accountID, repository, actor, randID(t))
			if err != nil || archived != 2 {
				t.Fatalf("archive exact repository = %d, %v; want 2, nil", archived, err)
			}
			sum := sha256.Sum256([]byte(repository))
			wantTarget := "sha256:" + hex.EncodeToString(sum[:])
			var targetID, otherStatus string
			if err := st.DB().QueryRowContext(ctx, `
				SELECT ae.target_id,sb.status
				FROM devradar_audit_event ae
				JOIN devradar_sbom sb ON sb.id=$2
				WHERE ae.account_id=$1 AND ae.action='repository.archive'`,
				accountID, other.ID).Scan(&targetID, &otherStatus); err != nil {
				t.Fatalf("read exact repository result: %v", err)
			}
			if targetID != wantTarget || len(targetID) != 71 || otherStatus != "active" {
				t.Fatalf("exact repository result = target %q/other %q, want %q/active", targetID, otherStatus, wantTarget)
			}

			archived, err = st.ArchiveRepoAudited(ctx, accountID, repository, actor, randID(t))
			if err != nil || archived != 0 {
				t.Fatalf("repeat exact repository archive = %d, %v", archived, err)
			}
			var audits int
			if err := st.DB().QueryRowContext(ctx, `
				SELECT count(*) FROM devradar_audit_event
				WHERE account_id=$1 AND action='repository.archive'`, accountID).Scan(&audits); err != nil {
				t.Fatalf("count exact repository audits: %v", err)
			}
			if audits != 1 {
				t.Fatalf("exact repository audit count = %d, want 1", audits)
			}
		})
	}
}

func TestAuditedArchiveInvalidRepositoryAuditFailureRollsBack(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, userID := seedAuditAccount(t, st)
	repository := " registry.test/team/rollback "
	first := seedTenantAndSBOMForAccount(t, st, accountID)
	second := seedTenantAndSBOMForAccount(t, st, accountID)
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_sbom SET repository=$2 WHERE id=ANY($1::text[])`,
		pq.Array([]string{first.ID, second.ID}), repository); err != nil {
		t.Fatalf("seed invalid repository: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		ALTER TABLE devradar_audit_event ADD CONSTRAINT test_reject_invalid_repository_archive
		CHECK (action <> 'repository.archive')`); err != nil {
		t.Fatalf("add repository audit failure: %v", err)
	}

	_, err := st.ArchiveRepoAudited(ctx, accountID, repository,
		account.Actor{Kind: account.ActorUser, UserID: userID}, randID(t))
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) || pqErr.Constraint != "test_reject_invalid_repository_archive" {
		t.Fatalf("archive audit failure = %v, want forced audit constraint", err)
	}
	var active, audits int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT count(*) FILTER (WHERE status='active'),
		       (SELECT count(*) FROM devradar_audit_event
		        WHERE account_id=$2 AND action='repository.archive')
		FROM devradar_sbom WHERE id=ANY($1::text[])`,
		pq.Array([]string{first.ID, second.ID}), accountID).Scan(&active, &audits); err != nil {
		t.Fatalf("read rolled back repository archive: %v", err)
	}
	if active != 2 || audits != 0 {
		t.Fatalf("repository after audit failure = active %d/audits %d", active, audits)
	}
}

func TestAuditedArchiveAuditFailuresRollBack(t *testing.T) {
	for _, tc := range []struct {
		name, action string
		mutate       func(*testing.T, *postgres.Store, string, account.Actor) (string, error)
	}{
		{
			name: "SBOM", action: "sbom.archive",
			mutate: func(t *testing.T, st *postgres.Store, accountID string, actor account.Actor) (string, error) {
				sb := seedTenantAndSBOMForAccount(t, st, accountID)
				return sb.ID, st.ArchiveSBOMAudited(context.Background(), accountID, sb.ID, actor, randID(t))
			},
		},
		{
			name: "repository", action: "repository.archive",
			mutate: func(t *testing.T, st *postgres.Store, accountID string, actor account.Actor) (string, error) {
				sb := seedTenantAndSBOMForAccount(t, st, accountID)
				_, err := st.ArchiveRepoAudited(context.Background(), accountID, sb.Repository, actor, randID(t))
				return sb.ID, err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := isolatedAdminProductHealthStore(t)
			ctx := context.Background()
			accountID, userID := seedAuditAccount(t, st)
			if _, err := st.DB().ExecContext(ctx, `
				ALTER TABLE devradar_audit_event ADD CONSTRAINT test_reject_archive
				CHECK (action <> $q$`+tc.action+`$q$)`); err != nil {
				t.Fatalf("add archive audit failure: %v", err)
			}
			sbomID, err := tc.mutate(t, st, accountID,
				account.Actor{Kind: account.ActorUser, UserID: userID})
			if err == nil {
				t.Fatal("archive audit failure returned nil")
			}
			var status string
			if err := st.DB().QueryRowContext(ctx,
				`SELECT status FROM devradar_sbom WHERE id=$1`, sbomID).Scan(&status); err != nil {
				t.Fatalf("read rolled back SBOM: %v", err)
			}
			if status != "active" {
				t.Fatalf("SBOM status after audit failure = %q, want active", status)
			}
		})
	}
}

func TestAuditedAPIIngestActivationAndAttestation(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, _ := seedAuditAccount(t, st)
	tokenID := seedAuditAPIToken(t, st, accountID)
	actor := account.Actor{Kind: account.ActorAPIToken, APITokenID: tokenID}
	sb := seedAuditPendingSBOM(t, st, accountID)

	if err := st.ActivateSBOMAudited(ctx, accountID, sb.ID, actor, randID(t)); err != nil {
		t.Fatalf("activate audited SBOM: %v", err)
	}
	if err := st.ActivateSBOMAudited(ctx, accountID, sb.ID, actor, randID(t)); err != nil {
		t.Fatalf("repeat activate audited SBOM: %v", err)
	}
	res := verifiedResult(sb.Digest)
	res.Envelope = []byte(`{"encrypted_payload":"must-not-copy"}`)
	if err := st.SaveAttestationAudited(ctx, accountID, sb.ID, res, actor, randID(t)); err != nil {
		t.Fatalf("save audited attestation: %v", err)
	}
	if err := st.SaveAttestationAudited(ctx, accountID, sb.ID, res, actor, randID(t)); err != nil {
		t.Fatalf("repeat save audited attestation: %v", err)
	}
	var evidenceID string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT id FROM devradar_sbom_attestation WHERE tenant_id=$1 AND sbom_id=$2`,
		accountID, sb.ID).Scan(&evidenceID); err != nil {
		t.Fatalf("read attestation evidence id: %v", err)
	}

	rows, err := st.DB().QueryContext(ctx, `
		SELECT action,target_type,target_id,actor_kind,actor_api_token_id::text,metadata::text
		FROM devradar_audit_event WHERE account_id=$1 ORDER BY id`, accountID)
	if err != nil {
		t.Fatalf("read ingest audits: %v", err)
	}
	defer func() { _ = rows.Close() }()
	want := []struct{ action, targetID string }{
		{"sbom.activate", sb.ID}, {"attestation.save", evidenceID},
	}
	seen := 0
	for ; rows.Next(); seen++ {
		i := seen
		if i >= len(want) {
			t.Fatal("idempotent ingest retry appended an extra audit event")
		}
		var action, targetType, targetID, kind, gotTokenID, metadata string
		if err := rows.Scan(&action, &targetType, &targetID, &kind, &gotTokenID, &metadata); err != nil {
			t.Fatalf("scan ingest audit: %v", err)
		}
		if action != want[i].action || targetID != want[i].targetID || kind != "api_token" || gotTokenID != tokenID {
			t.Fatalf("ingest audit %d = %s/%s/%s/%s/%s", i, action, targetType, targetID, kind, gotTokenID)
		}
		if strings.Contains(metadata, "must-not-copy") {
			t.Fatal("attestation envelope leaked into audit metadata")
		}
	}
	if seen != len(want) {
		t.Fatalf("ingest audit count = %d, want %d", seen, len(want))
	}
}

func TestSaveAttestationAuditedRepairsStatusWithPersistedEvidenceTarget(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, _ := seedAuditAccount(t, st)
	tokenID := seedAuditAPIToken(t, st, accountID)
	actor := account.Actor{Kind: account.ActorAPIToken, APITokenID: tokenID}
	sb := seedTenantAndSBOMForAccount(t, st, accountID)
	result := verifiedResult(sb.Digest)
	if err := st.SaveAttestation(ctx, accountID, sb.ID, result); err != nil {
		t.Fatalf("seed attestation evidence: %v", err)
	}
	var evidenceID string
	if err := st.DB().QueryRowContext(ctx, `
		SELECT id FROM devradar_sbom_attestation
		WHERE tenant_id=$1 AND sbom_id=$2 AND subject_digest=$3 AND policy_version=$4`,
		accountID, sb.ID, result.SubjectDigest, result.PolicyVersion).Scan(&evidenceID); err != nil {
		t.Fatalf("read persisted attestation evidence: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_sbom SET verification_status=$2 WHERE id=$1`,
		sb.ID, attest.StatusUnverified); err != nil {
		t.Fatalf("seed mismatched verification status: %v", err)
	}

	if err := st.SaveAttestationAudited(ctx, accountID, sb.ID, result, actor, randID(t)); err != nil {
		t.Fatalf("repair verification status: %v", err)
	}
	var targetID, targetTenantID, targetSBOMID, status string
	if err := st.DB().QueryRowContext(ctx, `
		SELECT ae.target_id,ev.tenant_id,ev.sbom_id,sb.verification_status
		FROM devradar_audit_event ae
		JOIN devradar_sbom_attestation ev ON ev.id::text=ae.target_id
		JOIN devradar_sbom sb ON sb.id=ev.sbom_id
		WHERE ae.account_id=$1 AND ae.action='attestation.save'`, accountID).
		Scan(&targetID, &targetTenantID, &targetSBOMID, &status); err != nil {
		t.Fatalf("read repaired attestation audit: %v", err)
	}
	if targetID != evidenceID || targetTenantID != accountID || targetSBOMID != sb.ID || status != attest.ResultVerified {
		t.Fatalf("repaired audit = target %q tenant %q SBOM %q status %q", targetID, targetTenantID, targetSBOMID, status)
	}

	if err := st.SaveAttestationAudited(ctx, accountID, sb.ID, result, actor, randID(t)); err != nil {
		t.Fatalf("retry repaired attestation: %v", err)
	}
	var audits int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT count(*) FROM devradar_audit_event
		WHERE account_id=$1 AND action='attestation.save'`, accountID).Scan(&audits); err != nil {
		t.Fatalf("count repaired attestation audits: %v", err)
	}
	if audits != 1 {
		t.Fatalf("repaired attestation audit count = %d, want 1", audits)
	}
}

func TestSaveAttestationAuditedAuditFailureRollsBackStatusRepair(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, _ := seedAuditAccount(t, st)
	tokenID := seedAuditAPIToken(t, st, accountID)
	sb := seedTenantAndSBOMForAccount(t, st, accountID)
	result := verifiedResult(sb.Digest)
	if err := st.SaveAttestation(ctx, accountID, sb.ID, result); err != nil {
		t.Fatalf("seed attestation evidence: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_sbom SET verification_status=$2 WHERE id=$1`,
		sb.ID, attest.StatusUnverified); err != nil {
		t.Fatalf("seed mismatched verification status: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		ALTER TABLE devradar_audit_event ADD CONSTRAINT test_reject_attestation_repair
		CHECK (action <> 'attestation.save')`); err != nil {
		t.Fatalf("add attestation repair audit failure: %v", err)
	}

	err := st.SaveAttestationAudited(ctx, accountID, sb.ID, result,
		account.Actor{Kind: account.ActorAPIToken, APITokenID: tokenID}, randID(t))
	if err == nil {
		t.Fatal("attestation repair audit failure returned nil")
	}
	var status string
	var audits int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT verification_status,
		       (SELECT count(*) FROM devradar_audit_event
		        WHERE account_id=$2 AND action='attestation.save')
		FROM devradar_sbom WHERE id=$1`, sb.ID, accountID).Scan(&status, &audits); err != nil {
		t.Fatalf("read rolled back attestation repair: %v", err)
	}
	if status != attest.StatusUnverified || audits != 0 {
		t.Fatalf("attestation repair after audit failure = status %q/audits %d", status, audits)
	}
}

func TestAuditedAPIIngestAuditFailuresRollBack(t *testing.T) {
	t.Run("activation remains pending", func(t *testing.T) {
		st := isolatedAdminProductHealthStore(t)
		ctx := context.Background()
		accountID, _ := seedAuditAccount(t, st)
		tokenID := seedAuditAPIToken(t, st, accountID)
		sb := seedAuditPendingSBOM(t, st, accountID)
		if _, err := st.DB().ExecContext(ctx, `
			ALTER TABLE devradar_audit_event ADD CONSTRAINT test_reject_activation
			CHECK (action <> 'sbom.activate')`); err != nil {
			t.Fatalf("add activation audit failure: %v", err)
		}
		if err := st.ActivateSBOMAudited(ctx, accountID, sb.ID,
			account.Actor{Kind: account.ActorAPIToken, APITokenID: tokenID}, randID(t)); err == nil {
			t.Fatal("activation audit failure returned nil")
		}
		var status string
		if err := st.DB().QueryRowContext(ctx,
			`SELECT status FROM devradar_sbom WHERE id=$1`, sb.ID).Scan(&status); err != nil {
			t.Fatalf("read pending SBOM: %v", err)
		}
		if status != "pending" {
			t.Fatalf("SBOM status = %q, want retryable pending after audit failure", status)
		}
	})

	t.Run("attestation evidence rolls back", func(t *testing.T) {
		st := isolatedAdminProductHealthStore(t)
		ctx := context.Background()
		accountID, _ := seedAuditAccount(t, st)
		tokenID := seedAuditAPIToken(t, st, accountID)
		sb := seedTenantAndSBOMForAccount(t, st, accountID)
		if _, err := st.DB().ExecContext(ctx, `
			ALTER TABLE devradar_audit_event ADD CONSTRAINT test_reject_attestation
			CHECK (action <> 'attestation.save')`); err != nil {
			t.Fatalf("add attestation audit failure: %v", err)
		}
		if err := st.SaveAttestationAudited(ctx, accountID, sb.ID, verifiedResult(sb.Digest),
			account.Actor{Kind: account.ActorAPIToken, APITokenID: tokenID}, randID(t)); err == nil {
			t.Fatal("attestation audit failure returned nil")
		}
		var evidence int
		var status string
		if err := st.DB().QueryRowContext(ctx, `
			SELECT (SELECT count(*) FROM devradar_sbom_attestation WHERE sbom_id=$1),
			       verification_status FROM devradar_sbom WHERE id=$1`, sb.ID).
			Scan(&evidence, &status); err != nil {
			t.Fatalf("read rolled back attestation: %v", err)
		}
		if evidence != 0 || status != attest.StatusUnverified {
			t.Fatalf("attestation after audit failure = evidence %d/status %s", evidence, status)
		}
	})
}

func TestActivateSBOMCompatibilityWrapper(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	accountID, _ := seedAuditAccount(t, st)
	sb := seedAuditPendingSBOM(t, st, accountID)
	if err := st.ActivateSBOM(context.Background(), sb.ID); err != nil {
		t.Fatalf("compatibility activation: %v", err)
	}
	var status string
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT status FROM devradar_sbom WHERE id=$1`, sb.ID).Scan(&status); err != nil {
		t.Fatalf("read compatibility activation: %v", err)
	}
	if status != "active" {
		t.Fatalf("compatibility activation status = %q, want active", status)
	}
}

func seedAuditAPIToken(t *testing.T, st *postgres.Store, accountID string) string {
	t.Helper()
	var tokenID string
	if err := st.DB().QueryRowContext(context.Background(), `
		INSERT INTO devradar_api_token (tenant_id,name,token_hash)
		VALUES ($1,'api actor',$2) RETURNING id`, accountID, randID(t)).Scan(&tokenID); err != nil {
		t.Fatalf("seed audit API token: %v", err)
	}
	return tokenID
}

func seedAuditPendingSBOM(t *testing.T, st *postgres.Store, accountID string) *postgres.SBOM {
	t.Helper()
	suffix := randID(t)
	sb := &postgres.SBOM{
		ID: suffix + randID(t), TenantID: accountID,
		ImageRef: "registry.test/pending:" + suffix[:8], Repository: "registry.test/pending",
		Digest: "sha256:" + randID(t) + randID(t), Format: "cyclonedx",
		ObjectPath: "gs://test/" + accountID + "/" + suffix, Status: "pending",
	}
	if _, _, _, err := st.UpsertSBOM(context.Background(), sb); err != nil {
		t.Fatalf("seed pending SBOM: %v", err)
	}
	return sb
}

func seedTenantAndSBOMForAccount(t *testing.T, st *postgres.Store, accountID string) *postgres.SBOM {
	t.Helper()
	suffix := randID(t)
	sb := &postgres.SBOM{
		ID: suffix + randID(t), TenantID: accountID,
		ImageRef: "registry.test/audit:" + suffix[:8], Repository: "registry.test/audit",
		Digest: "sha256:" + randID(t) + randID(t), Format: "cyclonedx",
		ObjectPath: "gs://test/" + accountID + "/" + suffix, Status: "active",
	}
	if _, _, _, err := st.UpsertSBOM(context.Background(), sb); err != nil {
		t.Fatalf("seed migration sbom: %v", err)
	}
	return sb
}

func seedMigrationAlert(t *testing.T, st *postgres.Store, accountID, policyID, sbomID string, read bool) string {
	t.Helper()
	readAt := any(nil)
	if read {
		readAt = time.Now().UTC()
	}
	var id string
	if err := st.DB().QueryRowContext(context.Background(), `
		INSERT INTO devradar_alert
			(tenant_id,policy_id,event_id,event_occurred_at,alert_kind,sbom_id,
			 repository,digest,finding_id,exposure,package,version,severity,score,cause,read_at)
		VALUES ($1,$2,$3,now(),'new_finding',$4,'registry.test/audit',$5,$6,$7,'pkg','1','high',8,'image',$8)
		RETURNING id`, accountID, policyID, time.Now().UnixNano(), sbomID,
		"sha256:"+randID(t)+randID(t), randID(t), "CVE-2099-"+randID(t)[:4], readAt).
		Scan(&id); err != nil {
		t.Fatalf("seed migration alert: %v", err)
	}
	return id
}

package postgres_test

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/authn"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

func TestAPITokenFlashSessionIsolationAndAtomicCreate(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, adminID := seedAuditAccount(t, st)
	firstSession := createTokenSession(t, st, adminID, accountID, time.Hour)
	secondSession := createTokenSession(t, st, adminID, accountID, time.Hour)
	key := bytes.Repeat([]byte{0x41}, 32)

	if _, err := st.CreateAPIToken(ctx, accountID, adminID, authn.HashToken(firstSession),
		"first", time.Hour, 10, "request-first", key); err != nil {
		t.Fatalf("create first token: %v", err)
	}
	if _, err := st.CreateAPIToken(ctx, accountID, adminID, authn.HashToken(secondSession),
		"second", 0, 10, "request-second", key); err != nil {
		t.Fatalf("create second token: %v", err)
	}

	var tokenCount, auditCount int
	var creatorCount, expiringCount, correlatedAuditCount int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT count(*),count(*) FILTER (WHERE created_by_user_id=$2),
		       count(*) FILTER (WHERE expires_at IS NOT NULL),
		       (SELECT count(*) FROM devradar_audit_event
		        WHERE account_id=$1 AND action='api_token.create'),
		       (SELECT count(*) FROM devradar_audit_event e
		        JOIN devradar_api_token token ON token.id::text=e.target_id AND token.tenant_id=e.account_id
		        WHERE e.account_id=$1 AND e.action='api_token.create'
		          AND e.request_id IN ('request-first','request-second'))
		FROM devradar_api_token WHERE tenant_id=$1`, accountID, adminID).
		Scan(&tokenCount, &creatorCount, &expiringCount, &auditCount, &correlatedAuditCount); err != nil {
		t.Fatal(err)
	}
	if tokenCount != 2 || creatorCount != 2 || expiringCount != 1 || auditCount != 2 || correlatedAuditCount != 2 {
		t.Fatalf("created token state = tokens %d creators %d expiring %d audits %d correlated %d",
			tokenCount, creatorCount, expiringCount, auditCount, correlatedAuditCount)
	}
	var stored string
	if err := st.DB().QueryRowContext(ctx, `
		SELECT value FROM devradar_session_token_flash
		WHERE session_id=$1 AND account_id=$2`, authn.HashToken(firstSession), accountID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, "enc:") || strings.Contains(stored, "dr_") {
		t.Fatalf("flash stored insecurely: %q", stored)
	}

	firstRaw, err := st.ConsumeTokenFlash(ctx, authn.HashToken(firstSession), accountID, key)
	if err != nil || !strings.HasPrefix(firstRaw, "dr_") {
		t.Fatalf("consume first flash = %q, %v", firstRaw, err)
	}
	if again, err := st.ConsumeTokenFlash(ctx, authn.HashToken(firstSession), accountID, key); err != nil || again != "" {
		t.Fatalf("consume first flash again = %q, %v", again, err)
	}
	secondRaw, err := st.ConsumeTokenFlash(ctx, authn.HashToken(secondSession), accountID, key)
	if err != nil || !strings.HasPrefix(secondRaw, "dr_") || secondRaw == firstRaw {
		t.Fatalf("consume second flash = %q, %v", secondRaw, err)
	}
	if _, _, err := st.ValidateAPIToken(ctx, firstRaw); err != nil {
		t.Fatalf("validate first raw token: %v", err)
	}
	if _, _, err := st.ValidateAPIToken(ctx, secondRaw); err != nil {
		t.Fatalf("validate second raw token: %v", err)
	}
	var leaked bool
	if err := st.DB().QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM devradar_audit_event
			WHERE account_id=$1 AND metadata::text LIKE '%dr_%'
		)`, accountID).Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked {
		t.Fatal("raw token leaked into audit metadata")
	}
}

func TestAPITokenCreateReturnsStableIDForCompensation(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, adminID := seedAuditAccount(t, st)
	session := createTokenSession(t, st, adminID, accountID, time.Hour)
	key := bytes.Repeat([]byte{0x19}, 32)
	requestID := randID(t)
	tokenID, err := st.CreateAPIToken(ctx, accountID, adminID, authn.HashToken(session),
		"compensate", 0, 10, requestID, key)
	if err != nil || tokenID == "" {
		t.Fatalf("create token handle = %q, %v", tokenID, err)
	}
	var persistedID, auditTarget string
	if err := st.DB().QueryRowContext(ctx, `
		SELECT token.id,e.target_id
		FROM devradar_api_token token
		JOIN devradar_audit_event e ON e.account_id=token.tenant_id
		  AND e.action='api_token.create' AND e.request_id=$3
		WHERE token.tenant_id=$1 AND token.id=$2`, accountID, tokenID, requestID).
		Scan(&persistedID, &auditTarget); err != nil {
		t.Fatal(err)
	}
	if persistedID != tokenID || auditTarget != tokenID {
		t.Fatalf("stable create handle = %s/%s, want %s", persistedID, auditTarget, tokenID)
	}
	if _, err := st.ConsumeTokenFlash(ctx, authn.HashToken(session), accountID,
		bytes.Repeat([]byte{0x29}, 32)); err == nil {
		t.Fatal("forced consume failure returned nil")
	}
	actor := account.Actor{Kind: account.ActorUser, UserID: adminID}
	if err := st.RevokeAPIToken(ctx, accountID, tokenID, actor, randID(t)); err != nil {
		t.Fatalf("compensating revoke: %v", err)
	}
	if err := st.DestroySession(ctx, session); err != nil {
		t.Fatalf("destroy compensating session: %v", err)
	}
	assertTokenMutationCounts(t, st, accountID, 0, 2, 0)
}

func TestTokenFlashAuthenticationFailureRetainsRow(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, adminID := seedAuditAccount(t, st)
	session := createTokenSession(t, st, adminID, accountID, time.Hour)
	key := bytes.Repeat([]byte{0x31}, 32)
	if _, err := st.CreateAPIToken(ctx, accountID, adminID, authn.HashToken(session),
		"recoverable", 0, 10, randID(t), key); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ConsumeTokenFlash(ctx, authn.HashToken(session), accountID, nil); err == nil {
		t.Fatal("missing key consumed flash")
	}
	if _, err := st.ConsumeTokenFlash(ctx, authn.HashToken(session), accountID,
		bytes.Repeat([]byte{0x32}, 32)); err == nil {
		t.Fatal("wrong key consumed flash")
	}
	var count int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT count(*) FROM devradar_session_token_flash
		WHERE session_id=$1 AND account_id=$2`, authn.HashToken(session), accountID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("flash rows after authentication failure = %d, want 1", count)
	}
	otherAccountID := seedAccountMembership(t, st, adminID, string(account.RoleAdmin))
	if err := st.SelectSessionAccount(ctx, session, adminID, otherAccountID); err != nil {
		t.Fatal(err)
	}
	if raw, err := st.ConsumeTokenFlash(ctx, authn.HashToken(session), accountID, key); err != nil || raw != "" {
		t.Fatalf("inactive-account consume = %q, %v, want empty", raw, err)
	}
	if err := st.SelectSessionAccount(ctx, session, adminID, accountID); err != nil {
		t.Fatal(err)
	}
	raw, err := st.ConsumeTokenFlash(ctx, authn.HashToken(session), accountID, key)
	if err != nil || !strings.HasPrefix(raw, "dr_") {
		t.Fatalf("recover retained flash = %q, %v", raw, err)
	}
}

func TestTokenFlashConcurrentConsumeReturnsSecretAtMostOnce(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, adminID := seedAuditAccount(t, st)
	session := createTokenSession(t, st, adminID, accountID, time.Hour)
	key := bytes.Repeat([]byte{0x71}, 32)
	if _, err := st.CreateAPIToken(ctx, accountID, adminID, authn.HashToken(session),
		"one-time", 0, 10, randID(t), key); err != nil {
		t.Fatal(err)
	}
	type result struct {
		raw string
		err error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			<-start
			raw, err := st.ConsumeTokenFlash(ctx, authn.HashToken(session), accountID, key)
			results <- result{raw: raw, err: err}
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("concurrent consumes = %v/%v", first.err, second.err)
	}
	nonempty := 0
	for _, raw := range []string{first.raw, second.raw} {
		if raw != "" {
			nonempty++
			if !strings.HasPrefix(raw, "dr_") {
				t.Fatalf("consumed value = %q", raw)
			}
		}
	}
	if nonempty != 1 {
		t.Fatalf("non-empty concurrent consumes = %d, want 1", nonempty)
	}
}

func TestAPITokenManagementRequiresActiveAdminAndExactSession(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, adminID := seedAuditAccount(t, st)
	editorID := seedAccountMember(t, st, accountID, account.RoleEditor, adminID)
	readerID := seedAccountMember(t, st, accountID, account.RoleReader, adminID)
	adminSession := createTokenSession(t, st, adminID, accountID, time.Hour)
	key := bytes.Repeat([]byte{0x52}, 32)
	adminActor := account.Actor{Kind: account.ActorUser, UserID: adminID}

	for _, tc := range []struct {
		name      string
		userID    string
		sessionID string
		prepare   func()
	}{
		{name: "editor", userID: editorID, sessionID: createTokenSession(t, st, editorID, accountID, time.Hour)},
		{name: "reader", userID: readerID, sessionID: createTokenSession(t, st, readerID, accountID, time.Hour)},
		{name: "different user session", userID: adminID, sessionID: createTokenSession(t, st, editorID, accountID, time.Hour)},
		{name: "expired session", userID: adminID, sessionID: createTokenSession(t, st, adminID, accountID, -time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := st.CreateAPIToken(ctx, accountID, tc.userID, authn.HashToken(tc.sessionID),
				tc.name, 0, 10, randID(t), key); err == nil {
				t.Fatal("unauthorized create succeeded")
			}
		})
	}
	otherAccountID := seedAccountMembership(t, st, adminID, string(account.RoleAdmin))
	otherSession := createTokenSession(t, st, adminID, otherAccountID, time.Hour)
	if _, err := st.CreateAPIToken(ctx, accountID, adminID, authn.HashToken(otherSession),
		"wrong active account", 0, 10, randID(t), key); err == nil {
		t.Fatal("cross-account session create succeeded")
	}
	assertTokenMutationCounts(t, st, accountID, 0, 0, 0)

	if _, err := st.CreateAPIToken(ctx, accountID, adminID, authn.HashToken(adminSession),
		"managed", 0, 10, randID(t), key); err != nil {
		t.Fatal(err)
	}
	tokens, err := st.ListAPITokens(ctx, accountID, adminActor)
	if err != nil || len(tokens) != 1 {
		t.Fatalf("admin list = %d, %v", len(tokens), err)
	}
	for _, userID := range []string{editorID, readerID} {
		actor := account.Actor{Kind: account.ActorUser, UserID: userID}
		if _, err := st.ListAPITokens(ctx, accountID, actor); err == nil {
			t.Fatalf("%s listed token metadata", userID)
		}
		if err := st.RevokeAPIToken(ctx, accountID, tokens[0].ID, actor, randID(t)); err == nil {
			t.Fatalf("%s revoked token", userID)
		}
	}
	assertTokenMutationCounts(t, st, accountID, 1, 1, 1)

	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_user SET status='suspended' WHERE id=$1`, adminID); err != nil {
		t.Fatal(err)
	}
	if err := st.RevokeAPIToken(ctx, accountID, tokens[0].ID, adminActor, randID(t)); err == nil {
		t.Fatal("suspended admin revoked token")
	}
	assertTokenMutationCounts(t, st, accountID, 1, 1, 1)
}

func TestAPITokenCreateRevalidatesActiveAuthorizationPredicates(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(context.Context, *postgres.Store, string, string) error
	}{
		{name: "revoked membership", prepare: func(ctx context.Context, st *postgres.Store, accountID, userID string) error {
			_, err := st.DB().ExecContext(ctx, `
				UPDATE devradar_account_member SET revoked_at=now()
				WHERE account_id=$1 AND user_id=$2`, accountID, userID)
			return err
		}},
		{name: "suspended user", prepare: func(ctx context.Context, st *postgres.Store, _, userID string) error {
			_, err := st.DB().ExecContext(ctx,
				`UPDATE devradar_user SET status='suspended' WHERE id=$1`, userID)
			return err
		}},
		{name: "suspended account", prepare: func(ctx context.Context, st *postgres.Store, accountID, _ string) error {
			_, err := st.DB().ExecContext(ctx,
				`UPDATE devradar_tenant SET status='suspended' WHERE id=$1`, accountID)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := isolatedAdminProductHealthStore(t)
			ctx := context.Background()
			accountID, adminID := seedAuditAccount(t, st)
			session := createTokenSession(t, st, adminID, accountID, time.Hour)
			if err := tc.prepare(ctx, st, accountID, adminID); err != nil {
				t.Fatal(err)
			}
			if _, err := st.CreateAPIToken(ctx, accountID, adminID, authn.HashToken(session),
				tc.name, 0, 10, randID(t), bytes.Repeat([]byte{3}, 32)); err == nil {
				t.Fatal("unauthorized create succeeded")
			}
			assertTokenMutationCounts(t, st, accountID, 0, 0, 0)
		})
	}
}

func TestAPITokenCreateSerializesWithMembershipChange(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, adminID := seedAuditAccount(t, st)
	session := createTokenSession(t, st, adminID, accountID, time.Hour)

	tx, err := st.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	var holderPID int
	if err := tx.QueryRowContext(ctx, `
		SELECT pg_backend_pid() FROM devradar_tenant WHERE id=$1 FOR UPDATE`, accountID).
		Scan(&holderPID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE devradar_account_member SET role='editor',updated_at=now()
		WHERE account_id=$1 AND user_id=$2`, accountID, adminID); err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	requestID := randID(t)
	go func() {
		_, err := st.CreateAPIToken(ctx, accountID, adminID, authn.HashToken(session),
			"raced", 0, 10, requestID, bytes.Repeat([]byte{8}, 32))
		result <- err
	}()
	if !waitForPostgresBlockers(ctx, st.DB(), holderPID, 1, 5*time.Second) {
		select {
		case err := <-result:
			t.Fatalf("token create did not serialize with membership lock: %v", err)
		default:
			t.Fatal("token create did not reach the membership lock")
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, postgres.ErrForbidden) {
		t.Fatalf("token create after demotion = %v, want ErrForbidden", err)
	}
	assertTokenMutationCounts(t, st, accountID, 0, 0, 0)
}

func TestAPITokenCreateCapAndAtomicFailures(t *testing.T) {
	t.Run("exact cap under concurrency", func(t *testing.T) {
		st := isolatedAdminProductHealthStore(t)
		ctx := context.Background()
		accountID, adminID := seedAuditAccount(t, st)
		session := createTokenSession(t, st, adminID, accountID, time.Hour)
		start := make(chan struct{})
		results := make(chan error, 2)
		var ready sync.WaitGroup
		ready.Add(2)
		requestIDs := []string{randID(t), randID(t)}
		for i := range 2 {
			go func(requestID string) {
				ready.Done()
				<-start
				_, err := st.CreateAPIToken(ctx, accountID, adminID, authn.HashToken(session),
					"bounded", 0, 1, requestID, bytes.Repeat([]byte{0x61}, 32))
				results <- err
			}(requestIDs[i])
		}
		ready.Wait()
		close(start)
		first, second := <-results, <-results
		if (first == nil) == (second == nil) {
			t.Fatalf("concurrent results = %v, %v, want one success", first, second)
		}
		failure := first
		if failure == nil {
			failure = second
		}
		if !errors.Is(failure, postgres.ErrAPITokenLimit) {
			t.Fatalf("cap failure = %v, want ErrAPITokenLimit", failure)
		}
		assertTokenMutationCounts(t, st, accountID, 1, 1, 1)
	})

	for _, tc := range []struct {
		name       string
		constraint string
		key        []byte
	}{
		{name: "audit failure", constraint: `ALTER TABLE devradar_audit_event
			ADD CONSTRAINT reject_token_create CHECK (action <> 'api_token.create')`, key: bytes.Repeat([]byte{1}, 32)},
		{name: "flash failure", constraint: `ALTER TABLE devradar_session_token_flash
			ADD CONSTRAINT reject_token_flash CHECK (false)`, key: bytes.Repeat([]byte{2}, 32)},
		{name: "invalid encryption key", key: []byte("invalid")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := isolatedAdminProductHealthStore(t)
			ctx := context.Background()
			accountID, adminID := seedAuditAccount(t, st)
			session := createTokenSession(t, st, adminID, accountID, time.Hour)
			if tc.constraint != "" {
				if _, err := st.DB().ExecContext(ctx, tc.constraint); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := st.CreateAPIToken(ctx, accountID, adminID, authn.HashToken(session),
				"rollback", 0, 10, randID(t), tc.key); err == nil {
				t.Fatal("forced failure returned nil")
			}
			assertTokenMutationCounts(t, st, accountID, 0, 0, 0)
		})
	}
}

func TestPurgeLegacyTokenFlashes(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, _ := seedAuditAccount(t, st)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_token_flash (tenant_id,value,expires_at)
		VALUES ($1,'legacy-secret',now()+interval '2 minutes')`, accountID); err != nil {
		t.Fatal(err)
	}
	if err := st.PurgeLegacyTokenFlashes(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_token_flash`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("legacy token flashes after purge = %d", count)
	}
}

func createTokenSession(t *testing.T, st *postgres.Store, userID, accountID string, ttl time.Duration) string {
	t.Helper()
	raw, err := st.CreateSession(context.Background(), userID, &accountID, ttl)
	if err != nil {
		t.Fatalf("create token session: %v", err)
	}
	return raw
}

func assertTokenMutationCounts(t *testing.T, st *postgres.Store, accountID string, tokens, audits, flashes int) {
	t.Helper()
	var gotTokens, gotAudits, gotFlashes int
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT (SELECT count(*) FROM devradar_api_token WHERE tenant_id=$1),
		       (SELECT count(*) FROM devradar_audit_event
		        WHERE account_id=$1 AND action IN ('api_token.create','api_token.revoke')),
		       (SELECT count(*) FROM devradar_session_token_flash WHERE account_id=$1)`, accountID).
		Scan(&gotTokens, &gotAudits, &gotFlashes); err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	if gotTokens != tokens || gotAudits != audits || gotFlashes != flashes {
		t.Fatalf("token state = %d tokens/%d audits/%d flashes, want %d/%d/%d",
			gotTokens, gotAudits, gotFlashes, tokens, audits, flashes)
	}
}

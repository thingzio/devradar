package postgres_test

import (
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

func TestResolveDirectIdentityCreatesOneAccount(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	email := "new-" + randID(t)[:8] + "@example.com"
	id := account.VerifiedIdentity{Provider: "magiclink", Subject: email, Email: email}

	user, acct, err := st.ResolveDirectIdentity(ctx, id)
	if err != nil {
		t.Fatalf("resolve direct identity: %v", err)
	}
	if acct == nil || user.ID == acct.ID || acct.Name != email {
		t.Fatalf("resolve = %#v %#v, want distinct user/account named %q", user, acct, email)
	}
	secondUser, secondAccount, err := st.ResolveDirectIdentity(ctx, id)
	if err != nil {
		t.Fatalf("resolve direct identity again: %v", err)
	}
	if secondAccount == nil || secondUser.ID != user.ID || secondAccount.ID != acct.ID {
		t.Fatalf("repeat resolve = %#v %#v, want user/account %s/%s",
			secondUser, secondAccount, user.ID, acct.ID)
	}

	var users, accounts, memberships int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_user WHERE email=$1`, email).Scan(&users); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if err := st.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_tenant WHERE email=$1`, email).Scan(&accounts); err != nil {
		t.Fatalf("count accounts: %v", err)
	}
	if err := st.DB().QueryRowContext(ctx, `
		SELECT count(*) FROM devradar_account_member
		WHERE user_id=$1 AND account_id=$2 AND role='admin' AND revoked_at IS NULL`,
		user.ID, acct.ID).Scan(&memberships); err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if users != 1 || accounts != 1 || memberships != 1 {
		t.Fatalf("created users/accounts/admin memberships = %d/%d/%d, want 1/1/1",
			users, accounts, memberships)
	}
	var identityUserID, identityAccountID string
	if err := st.DB().QueryRowContext(ctx, `
		SELECT user_id,tenant_id FROM devradar_identity
		WHERE provider=$1 AND subject=$2`, id.Provider, id.Subject).
		Scan(&identityUserID, &identityAccountID); err != nil {
		t.Fatalf("read direct identity compatibility fields: %v", err)
	}
	if identityUserID != user.ID || identityAccountID != acct.ID {
		t.Fatalf("identity user/account = %s/%s, want %s/%s",
			identityUserID, identityAccountID, user.ID, acct.ID)
	}
}

func TestResolveDirectIdentityTruncatesAccountNameByUnicodeCodePoint(t *testing.T) {
	st := testStore(t)
	email := strings.Repeat("é", 85) + "-" + randID(t)[:8] + "@example.com"
	id := account.VerifiedIdentity{Provider: "magiclink", Subject: email, Email: email}

	_, acct, err := st.ResolveDirectIdentity(context.Background(), id)
	if err != nil {
		t.Fatalf("resolve direct identity: %v", err)
	}
	if acct == nil || len([]rune(acct.Name)) != 80 || acct.Name != strings.Repeat("é", 80) {
		t.Fatalf("account name = %q (%d runes), want first 80 code points",
			acct.Name, len([]rune(acct.Name)))
	}
}

func TestResolveDirectIdentityProviderSubjectOwnsLaterEmailChanges(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	firstEmail := "subject-first-" + randID(t)[:8] + "@example.com"
	changedEmail := "subject-changed-" + randID(t)[:8] + "@example.com"
	id := account.VerifiedIdentity{
		Provider: "github", Subject: randID(t), Email: firstEmail,
		AvatarURL: "https://example.com/first.png",
	}
	firstUser, firstAccount, err := st.ResolveDirectIdentity(ctx, id)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	id.Email = changedEmail
	id.AvatarURL = "https://example.com/changed.png"
	secondUser, secondAccount, err := st.ResolveDirectIdentity(ctx, id)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if secondUser.ID != firstUser.ID || secondUser.Email != firstEmail || secondUser.AvatarURL != id.AvatarURL {
		t.Fatalf("second user = %#v, want original owner %s/%s with refreshed avatar",
			secondUser, firstUser.ID, firstEmail)
	}
	if secondAccount == nil || firstAccount == nil || secondAccount.ID != firstAccount.ID {
		t.Fatalf("second account = %#v, want original %#v", secondAccount, firstAccount)
	}
	var changedUsers int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_user WHERE email=$1`, changedEmail).Scan(&changedUsers); err != nil {
		t.Fatalf("count changed-email users: %v", err)
	}
	if changedUsers != 0 {
		t.Fatalf("later provider email created %d users, want 0", changedUsers)
	}
}

func TestResolveDirectIdentityConcurrentFirstLoginCreatesOneUserAccount(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	email := "concurrent-" + randID(t)[:8] + "@example.com"
	id := account.VerifiedIdentity{Provider: "github", Subject: randID(t), Email: email}

	const attempts = 8
	type result struct {
		userID    string
		accountID string
		err       error
	}
	start := make(chan struct{})
	results := make(chan result, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			u, a, err := st.ResolveDirectIdentity(ctx, id)
			r := result{err: err}
			if u != nil {
				r.userID = u.ID
			}
			if a != nil {
				r.accountID = a.ID
			}
			results <- r
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var want result
	for got := range results {
		if got.err != nil {
			t.Fatalf("concurrent resolve: %v", got.err)
		}
		if got.userID == "" || got.accountID == "" {
			t.Fatalf("concurrent resolve returned empty IDs: %#v", got)
		}
		if want.userID == "" {
			want = got
			continue
		}
		if got.userID != want.userID || got.accountID != want.accountID {
			t.Fatalf("concurrent resolve = %s/%s, want %s/%s",
				got.userID, got.accountID, want.userID, want.accountID)
		}
	}

	var users, accounts, identities int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_user WHERE email=$1`, email).Scan(&users); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if err := st.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_tenant WHERE email=$1`, email).Scan(&accounts); err != nil {
		t.Fatalf("count accounts: %v", err)
	}
	if err := st.DB().QueryRowContext(ctx, `
		SELECT count(*) FROM devradar_identity WHERE provider=$1 AND subject=$2`,
		id.Provider, id.Subject).Scan(&identities); err != nil {
		t.Fatalf("count identities: %v", err)
	}
	if users != 1 || accounts != 1 || identities != 1 {
		t.Fatalf("concurrent users/accounts/identities = %d/%d/%d, want 1/1/1",
			users, accounts, identities)
	}
}

func TestResolveDirectIdentityConcurrentSubjectsWithSameNormalizedEmail(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	for run := range 2 {
		email := "same-email-" + randID(t)[:8] + "@example.com"
		identities := []account.VerifiedIdentity{
			{Provider: "github", Subject: "github-" + randID(t), Email: "  " + strings.ToUpper(email) + "  "},
			{Provider: "magiclink", Subject: email, Email: email},
		}

		holder, err := st.DB().Conn(ctx)
		if err != nil {
			t.Fatalf("run %d acquire advisory-lock holder: %v", run, err)
		}
		var holderPID int
		if err := holder.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&holderPID); err != nil {
			_ = holder.Close()
			t.Fatalf("run %d read advisory-lock holder pid: %v", run, err)
		}
		if _, err := holder.ExecContext(ctx,
			`SELECT pg_advisory_lock(hashtext($1))`, email); err != nil {
			_ = holder.Close()
			t.Fatalf("run %d hold normalized-email lock: %v", run, err)
		}

		results := startConcurrentIdentityResolutions(st, identities)
		blocked := waitForPostgresBlockers(ctx, st.DB(), holderPID, len(identities), 5*time.Second)
		if _, err := holder.ExecContext(ctx,
			`SELECT pg_advisory_unlock(hashtext($1))`, email); err != nil {
			_ = holder.Close()
			t.Fatalf("run %d release normalized-email lock: %v", run, err)
		}
		if err := holder.Close(); err != nil {
			t.Fatalf("run %d close advisory-lock holder: %v", run, err)
		}
		resolved := collectIdentityResolutions(t, results, len(identities))
		if !blocked {
			t.Fatalf("run %d identity resolutions did not both wait on normalized-email advisory lock", run)
		}
		assertSameResolvedIdentity(t, resolved)

		var users, accounts, memberships, identityLinks, distinctIdentityUsers int
		if err := st.DB().QueryRowContext(ctx,
			`SELECT count(*) FROM devradar_user WHERE email=$1`, email).Scan(&users); err != nil {
			t.Fatalf("run %d count users: %v", run, err)
		}
		if err := st.DB().QueryRowContext(ctx,
			`SELECT count(*) FROM devradar_tenant WHERE email=$1`, email).Scan(&accounts); err != nil {
			t.Fatalf("run %d count accounts: %v", run, err)
		}
		if err := st.DB().QueryRowContext(ctx, `
			SELECT count(*) FROM devradar_account_member
			WHERE user_id=$1 AND account_id=$2 AND role='admin' AND revoked_at IS NULL`,
			resolved[0].userID, resolved[0].accountID).Scan(&memberships); err != nil {
			t.Fatalf("run %d count admin memberships: %v", run, err)
		}
		if err := st.DB().QueryRowContext(ctx, `
			SELECT count(*),count(DISTINCT user_id) FROM devradar_identity
			WHERE (provider=$1 AND subject=$2) OR (provider=$3 AND subject=$4)`,
			identities[0].Provider, identities[0].Subject,
			identities[1].Provider, identities[1].Subject).
			Scan(&identityLinks, &distinctIdentityUsers); err != nil {
			t.Fatalf("run %d count identity links: %v", run, err)
		}
		if users != 1 || accounts != 1 || memberships != 1 || identityLinks != 2 || distinctIdentityUsers != 1 {
			t.Fatalf("run %d users/accounts/admins/links/distinct owners = %d/%d/%d/%d/%d, want 1/1/1/2/1",
				run, users, accounts, memberships, identityLinks, distinctIdentityUsers)
		}
	}
}

func TestResolveDirectIdentityConcurrentEmailsWithSameSubjectRollsBackLoser(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	for run := range 2 {
		subject := "shared-subject-" + randID(t)
		emailA := "subject-a-" + randID(t)[:8] + "@example.com"
		emailB := "subject-b-" + randID(t)[:8] + "@example.com"
		identities := []account.VerifiedIdentity{
			{Provider: "github", Subject: subject, Email: emailA},
			{Provider: "github", Subject: subject, Email: emailB},
		}

		holder, err := st.DB().Conn(ctx)
		if err != nil {
			t.Fatalf("run %d acquire identity-lock holder: %v", run, err)
		}
		tx, err := holder.BeginTx(ctx, nil)
		if err != nil {
			_ = holder.Close()
			t.Fatalf("run %d begin identity-lock transaction: %v", run, err)
		}
		var holderPID int
		if err := tx.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&holderPID); err != nil {
			_ = tx.Rollback()
			_ = holder.Close()
			t.Fatalf("run %d read identity-lock holder pid: %v", run, err)
		}
		if _, err := tx.ExecContext(ctx, `LOCK TABLE devradar_identity IN SHARE MODE`); err != nil {
			_ = tx.Rollback()
			_ = holder.Close()
			t.Fatalf("run %d lock identity insertion: %v", run, err)
		}

		results := startConcurrentIdentityResolutions(st, identities)
		blocked := waitForPostgresBlockers(ctx, st.DB(), holderPID, len(identities), 5*time.Second)
		if err := tx.Commit(); err != nil {
			_ = holder.Close()
			t.Fatalf("run %d release identity insertion lock: %v", run, err)
		}
		if err := holder.Close(); err != nil {
			t.Fatalf("run %d close identity-lock holder: %v", run, err)
		}
		resolved := collectIdentityResolutions(t, results, len(identities))
		if !blocked {
			t.Fatalf("run %d identity resolutions did not both reach the identity insert barrier", run)
		}
		assertSameResolvedIdentity(t, resolved)

		var users, accounts, memberships, identityLinks, orphanUsers, orphanAccounts int
		if err := st.DB().QueryRowContext(ctx,
			`SELECT count(*) FROM devradar_user WHERE email IN ($1,$2)`, emailA, emailB).Scan(&users); err != nil {
			t.Fatalf("run %d count users: %v", run, err)
		}
		if err := st.DB().QueryRowContext(ctx,
			`SELECT count(*) FROM devradar_tenant WHERE email IN ($1,$2)`, emailA, emailB).Scan(&accounts); err != nil {
			t.Fatalf("run %d count accounts: %v", run, err)
		}
		if err := st.DB().QueryRowContext(ctx, `
			SELECT count(*) FROM devradar_account_member m
			JOIN devradar_tenant a ON a.id=m.account_id
			WHERE a.email IN ($1,$2)`, emailA, emailB).Scan(&memberships); err != nil {
			t.Fatalf("run %d count memberships: %v", run, err)
		}
		if err := st.DB().QueryRowContext(ctx, `
			SELECT count(*) FROM devradar_identity WHERE provider='github' AND subject=$1`, subject).
			Scan(&identityLinks); err != nil {
			t.Fatalf("run %d count identity links: %v", run, err)
		}
		if err := st.DB().QueryRowContext(ctx, `
			SELECT count(*) FROM devradar_user u
			LEFT JOIN devradar_identity i ON i.user_id=u.id
			WHERE u.email IN ($1,$2) AND i.id IS NULL`, emailA, emailB).Scan(&orphanUsers); err != nil {
			t.Fatalf("run %d count orphan users: %v", run, err)
		}
		if err := st.DB().QueryRowContext(ctx, `
			SELECT count(*) FROM devradar_tenant a
			LEFT JOIN devradar_identity i ON i.tenant_id=a.id
			WHERE a.email IN ($1,$2) AND i.id IS NULL`, emailA, emailB).Scan(&orphanAccounts); err != nil {
			t.Fatalf("run %d count orphan accounts: %v", run, err)
		}
		if users != 1 || accounts != 1 || memberships != 1 || identityLinks != 1 || orphanUsers != 0 || orphanAccounts != 0 {
			t.Fatalf("run %d users/accounts/memberships/links/orphan users/orphan accounts = %d/%d/%d/%d/%d/%d, want 1/1/1/1/0/0",
				run, users, accounts, memberships, identityLinks, orphanUsers, orphanAccounts)
		}
	}
}

func TestResolveDirectIdentityExistingZeroMembershipUserGetsNoAccount(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	email := "memberless-" + randID(t)[:8] + "@example.com"
	var userID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_user (email,email_verified_at) VALUES ($1,now()) RETURNING id`, email).
		Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	id := account.VerifiedIdentity{Provider: "magiclink", Subject: email, Email: email}

	user, acct, err := st.ResolveDirectIdentity(ctx, id)
	if err != nil {
		t.Fatalf("resolve existing user: %v", err)
	}
	if user.ID != userID || acct != nil {
		t.Fatalf("resolve existing user = %#v %#v, want %s and nil account", user, acct, userID)
	}
	var accountCount int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_tenant WHERE email=$1`, email).Scan(&accountCount); err != nil {
		t.Fatalf("count personal accounts: %v", err)
	}
	if accountCount != 0 {
		t.Fatalf("existing memberless user received %d personal accounts, want 0", accountCount)
	}
	var compatibilityAccount *string
	if err := st.DB().QueryRowContext(ctx, `
		SELECT tenant_id FROM devradar_identity WHERE provider=$1 AND subject=$2`,
		id.Provider, id.Subject).Scan(&compatibilityAccount); err != nil {
		t.Fatalf("read compatibility account: %v", err)
	}
	if compatibilityAccount != nil {
		t.Fatalf("existing user identity compatibility account = %q, want NULL", *compatibilityAccount)
	}
}

func TestResolveDirectIdentityAutoSelectsExactlyOneActiveMembership(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	email := "memberships-" + randID(t)[:8] + "@example.com"
	var userID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_user (email,email_verified_at) VALUES ($1,now()) RETURNING id`, email).
		Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	firstAccountID := seedAccountMembership(t, st, userID, "editor")
	id := account.VerifiedIdentity{Provider: "github", Subject: randID(t), Email: email}

	_, only, err := st.ResolveDirectIdentity(ctx, id)
	if err != nil {
		t.Fatalf("resolve one membership: %v", err)
	}
	if only == nil || only.ID != firstAccountID {
		t.Fatalf("one membership selected %#v, want %s", only, firstAccountID)
	}
	_ = seedAccountMembership(t, st, userID, "reader")
	_, multiple, err := st.ResolveDirectIdentity(ctx, id)
	if err != nil {
		t.Fatalf("resolve multiple memberships: %v", err)
	}
	if multiple != nil {
		t.Fatalf("multiple memberships selected %#v, want nil", multiple)
	}
}

func TestSessionDualWriteValidationAndSelection(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	email := "session-" + randID(t)[:8] + "@example.com"
	user, firstAccount, err := st.ResolveDirectIdentity(ctx, account.VerifiedIdentity{
		Provider: "magiclink", Subject: email, Email: email,
	})
	if err != nil {
		t.Fatalf("resolve direct identity: %v", err)
	}
	secondAccountID := seedAccountMembership(t, st, user.ID, "reader")

	raw, err := st.CreateSession(ctx, user.ID, &firstAccount.ID, time.Hour)
	if err != nil {
		t.Fatalf("create selected session: %v", err)
	}
	assertSessionAccounts(t, st, raw, &firstAccount.ID, &firstAccount.ID)
	session, err := st.ValidateSession(ctx, raw)
	if err != nil {
		t.Fatalf("validate session: %v", err)
	}
	if session.User.ID != user.ID || session.ActiveAccountID == nil || *session.ActiveAccountID != firstAccount.ID {
		t.Fatalf("validated session = %#v, want user/account %s/%s", session, user.ID, firstAccount.ID)
	}

	chooserRaw, err := st.CreateSession(ctx, user.ID, nil, time.Hour)
	if err != nil {
		t.Fatalf("create chooser session: %v", err)
	}
	assertSessionAccounts(t, st, chooserRaw, nil, nil)
	foreignUserEmail := "foreign-session-" + randID(t)[:8] + "@example.com"
	foreignUser, foreignAccount, err := st.ResolveDirectIdentity(ctx, account.VerifiedIdentity{
		Provider: "magiclink", Subject: foreignUserEmail, Email: foreignUserEmail,
	})
	if err != nil {
		t.Fatalf("resolve foreign identity: %v", err)
	}
	if err := st.SelectSessionAccount(ctx, chooserRaw, user.ID, foreignAccount.ID); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("select foreign membership error = %v, want ErrNotFound", err)
	}
	if err := st.SelectSessionAccount(ctx, chooserRaw, foreignUser.ID, secondAccountID); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("select with wrong session user error = %v, want ErrNotFound", err)
	}
	assertSessionAccounts(t, st, chooserRaw, nil, nil)
	if err := st.SelectSessionAccount(ctx, chooserRaw, user.ID, secondAccountID); err != nil {
		t.Fatalf("select active membership: %v", err)
	}
	assertSessionAccounts(t, st, chooserRaw, &secondAccountID, &secondAccountID)

	if err := st.DestroySession(ctx, chooserRaw); err != nil {
		t.Fatalf("destroy session: %v", err)
	}
	if _, err := st.ValidateSession(ctx, chooserRaw); !errors.Is(err, postgres.ErrSessionInvalid) {
		t.Fatalf("validate destroyed session error = %v, want ErrSessionInvalid", err)
	}
}

func TestSelectSessionAccountRevalidatesAuthorizationPredicates(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(context.Context, *postgres.Store, string, string) error
	}{
		{
			name: "revoked membership",
			mutate: func(ctx context.Context, st *postgres.Store, userID, accountID string) error {
				_, err := st.DB().ExecContext(ctx, `
					UPDATE devradar_account_member SET revoked_at=now()
					WHERE user_id=$1 AND account_id=$2`, userID, accountID)
				return err
			},
		},
		{
			name: "suspended user",
			mutate: func(ctx context.Context, st *postgres.Store, userID, _ string) error {
				_, err := st.DB().ExecContext(ctx,
					`UPDATE devradar_user SET status='suspended' WHERE id=$1`, userID)
				return err
			},
		},
		{
			name: "suspended account",
			mutate: func(ctx context.Context, st *postgres.Store, _ string, accountID string) error {
				_, err := st.DB().ExecContext(ctx,
					`UPDATE devradar_tenant SET status='suspended' WHERE id=$1`, accountID)
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := testStore(t)
			ctx := context.Background()
			email := "selection-" + randID(t)[:8] + "@example.com"
			user, acct, err := st.ResolveDirectIdentity(ctx, account.VerifiedIdentity{
				Provider: "magiclink", Subject: email, Email: email,
			})
			if err != nil {
				t.Fatalf("resolve direct identity: %v", err)
			}
			raw, err := st.CreateSession(ctx, user.ID, nil, time.Hour)
			if err != nil {
				t.Fatalf("create chooser session: %v", err)
			}
			if err := tt.mutate(ctx, st, user.ID, acct.ID); err != nil {
				t.Fatalf("mutate authorization state: %v", err)
			}
			if err := st.SelectSessionAccount(ctx, raw, user.ID, acct.ID); !errors.Is(err, postgres.ErrNotFound) {
				t.Fatalf("SelectSessionAccount error = %v, want ErrNotFound", err)
			}
			assertSessionAccounts(t, st, raw, nil, nil)
		})
	}
}

func TestSessionExpiredFails(t *testing.T) {
	st := testStore(t)
	email := "expired-session-" + randID(t)[:8] + "@example.com"
	user, acct, err := st.ResolveDirectIdentity(context.Background(), account.VerifiedIdentity{
		Provider: "magiclink", Subject: email, Email: email,
	})
	if err != nil {
		t.Fatalf("resolve direct identity: %v", err)
	}
	raw, err := st.CreateSession(context.Background(), user.ID, &acct.ID, -time.Second)
	if err != nil {
		t.Fatalf("create expired session: %v", err)
	}
	if _, err := st.ValidateSession(context.Background(), raw); !errors.Is(err, postgres.ErrSessionInvalid) {
		t.Fatalf("validate expired session error = %v, want ErrSessionInvalid", err)
	}
}

func TestSessionLegacyNullUserRepairPreservesExistingOwnershipAndMembership(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	accountEmail := "legacy-session-" + randID(t)[:8] + "@example.com"
	var accountID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_tenant (email,name,email_verified_at)
		VALUES ($1,$1,now()) RETURNING id`, accountEmail).Scan(&accountID); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	legacyEmail := "legacy-user-" + randID(t)[:8] + "@example.com"
	var legacyUserID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_user (email,email_verified_at,legacy_tenant_id)
		VALUES ($1,now(),$2) RETURNING id`, legacyEmail, accountID).Scan(&legacyUserID); err != nil {
		t.Fatalf("seed legacy user: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_account_member (account_id,user_id,role,revoked_at)
		VALUES ($1,$2,'admin',now())`, accountID, legacyUserID); err != nil {
		t.Fatalf("seed revoked membership: %v", err)
	}
	credentialEmail := "credential-owner-" + randID(t)[:8] + "@example.com"
	var credentialUserID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_user (email,email_verified_at) VALUES ($1,now()) RETURNING id`, credentialEmail).
		Scan(&credentialUserID); err != nil {
		t.Fatalf("seed credential owner: %v", err)
	}
	subject := randID(t)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_identity (tenant_id,user_id,provider,subject,email)
		VALUES ($1,$2,'github',$3,$4)`, accountID, credentialUserID, subject, credentialEmail); err != nil {
		t.Fatalf("seed existing credential ownership: %v", err)
	}
	raw := "legacy-raw-" + randID(t)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_session (id,tenant_id,user_id,active_account_id,expires_at)
		VALUES ($1,$2,NULL,NULL,now()+interval '1 hour')`, authn.HashToken(raw), accountID); err != nil {
		t.Fatalf("seed legacy session: %v", err)
	}

	session, err := st.ValidateSession(ctx, raw)
	if err != nil {
		t.Fatalf("validate legacy session: %v", err)
	}
	if session.User.ID != legacyUserID || session.ActiveAccountID != nil {
		t.Fatalf("repaired session = %#v, want legacy user %s with chooser", session, legacyUserID)
	}
	var gotCredentialUserID string
	if err := st.DB().QueryRowContext(ctx, `
		SELECT user_id FROM devradar_identity WHERE provider='github' AND subject=$1`, subject).
		Scan(&gotCredentialUserID); err != nil {
		t.Fatalf("read credential owner: %v", err)
	}
	if gotCredentialUserID != credentialUserID {
		t.Fatalf("credential owner = %s, want preserved %s", gotCredentialUserID, credentialUserID)
	}
	var revoked bool
	if err := st.DB().QueryRowContext(ctx, `
		SELECT revoked_at IS NOT NULL FROM devradar_account_member
		WHERE account_id=$1 AND user_id=$2`, accountID, legacyUserID).Scan(&revoked); err != nil {
		t.Fatalf("read membership: %v", err)
	}
	if !revoked {
		t.Fatal("legacy session repair reactivated revoked membership")
	}
}

func TestSessionLegacyNullUserCreatesMissingBackfill(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	email := "legacy-missing-" + randID(t)[:8] + "@example.com"
	var accountID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_tenant (email,name,email_verified_at)
		VALUES ($1,$1,now()) RETURNING id`, email).Scan(&accountID); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	raw := "legacy-missing-raw-" + randID(t)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_session (id,tenant_id,expires_at)
		VALUES ($1,$2,now()+interval '1 hour')`, authn.HashToken(raw), accountID); err != nil {
		t.Fatalf("seed legacy session: %v", err)
	}

	session, err := st.ValidateSession(ctx, raw)
	if err != nil {
		t.Fatalf("validate legacy session: %v", err)
	}
	if session.User.ID == accountID || session.ActiveAccountID == nil || *session.ActiveAccountID != accountID {
		t.Fatalf("repaired session = %#v, want distinct user and active account %s", session, accountID)
	}
	var memberships int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT count(*) FROM devradar_account_member
		WHERE account_id=$1 AND user_id=$2 AND role='admin' AND revoked_at IS NULL`,
		accountID, session.User.ID).Scan(&memberships); err != nil {
		t.Fatalf("count repaired membership: %v", err)
	}
	if memberships != 1 {
		t.Fatalf("repaired active admin memberships = %d, want 1", memberships)
	}
}

func TestSessionLegacyNullUserRepairsAllNullCompatibilityRows(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	email := "legacy-all-null-" + randID(t)[:8] + "@example.com"
	var accountID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_tenant (email,name,email_verified_at)
		VALUES ($1,'',now()) RETURNING id`, email).Scan(&accountID); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	var userID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_user (email,email_verified_at,legacy_tenant_id)
		VALUES ($1,now(),$2) RETURNING id`, email, accountID).Scan(&userID); err != nil {
		t.Fatalf("seed legacy user: %v", err)
	}
	subject := randID(t)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_identity (tenant_id,user_id,provider,subject,email)
		VALUES ($1,NULL,'github',$2,$3)`, accountID, subject, email); err != nil {
		t.Fatalf("seed null-owner identity: %v", err)
	}
	raw := "legacy-trigger-" + randID(t)
	siblingRaw := "legacy-sibling-" + randID(t)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_session (id,tenant_id,user_id,active_account_id,expires_at)
		VALUES ($1,$3,NULL,NULL,now()+interval '1 hour'),
		       ($2,$3,NULL,NULL,now()+interval '1 hour')`,
		authn.HashToken(raw), authn.HashToken(siblingRaw), accountID); err != nil {
		t.Fatalf("seed legacy sessions: %v", err)
	}

	session, err := st.ValidateSession(ctx, raw)
	if err != nil {
		t.Fatalf("validate trigger session: %v", err)
	}
	if session.User.ID != userID || session.ActiveAccountID == nil || *session.ActiveAccountID != accountID {
		t.Fatalf("trigger session = %#v, want %s/%s", session, userID, accountID)
	}
	var name, role, identityUserID, siblingUserID string
	var siblingActiveAccountID *string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT name FROM devradar_tenant WHERE id=$1`, accountID).Scan(&name); err != nil {
		t.Fatalf("read repaired account name: %v", err)
	}
	if err := st.DB().QueryRowContext(ctx, `
		SELECT role FROM devradar_account_member WHERE account_id=$1 AND user_id=$2`,
		accountID, userID).Scan(&role); err != nil {
		t.Fatalf("read repaired membership: %v", err)
	}
	if err := st.DB().QueryRowContext(ctx, `
		SELECT user_id FROM devradar_identity WHERE provider='github' AND subject=$1`, subject).
		Scan(&identityUserID); err != nil {
		t.Fatalf("read repaired identity: %v", err)
	}
	if err := st.DB().QueryRowContext(ctx, `
		SELECT user_id,active_account_id FROM devradar_session WHERE id=$1`,
		authn.HashToken(siblingRaw)).Scan(&siblingUserID, &siblingActiveAccountID); err != nil {
		t.Fatalf("read repaired sibling session: %v", err)
	}
	if name != email || role != "admin" || identityUserID != userID || siblingUserID != userID ||
		siblingActiveAccountID == nil || *siblingActiveAccountID != accountID {
		t.Fatalf("compatibility repair = name %q, role %q, identity %q, sibling %q/%v",
			name, role, identityUserID, siblingUserID, siblingActiveAccountID)
	}
}

func TestLoginTokenLifecycle(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	email := "login-token-" + randID(t)[:8] + "@example.com"
	raw, err := st.CreateLoginToken(ctx, "  "+strings.ToUpper(email)+"  ", time.Hour)
	if err != nil {
		t.Fatalf("create login token: %v", err)
	}
	peeked, err := st.PeekLoginToken(ctx, raw)
	if err != nil || peeked != email {
		t.Fatalf("peek login token = %q, %v, want %q", peeked, err, email)
	}
	id, err := st.ConsumeLoginToken(ctx, raw)
	if err != nil {
		t.Fatalf("consume login token: %v", err)
	}
	if id.Provider != "magiclink" || id.Subject != email || id.Email != email {
		t.Fatalf("consumed identity = %#v, want magiclink/%s", id, email)
	}
	if _, err := st.ConsumeLoginToken(ctx, raw); !errors.Is(err, postgres.ErrLoginTokenInvalid) {
		t.Fatalf("reuse login token error = %v, want ErrLoginTokenInvalid", err)
	}

	expired, err := st.CreateLoginToken(ctx, email, -time.Second)
	if err != nil {
		t.Fatalf("create expired login token: %v", err)
	}
	if _, err := st.PeekLoginToken(ctx, expired); !errors.Is(err, postgres.ErrLoginTokenExpired) {
		t.Fatalf("peek expired token error = %v, want ErrLoginTokenExpired", err)
	}
}

func seedAccountMembership(t *testing.T, st *postgres.Store, userID, role string) string {
	t.Helper()
	ctx := context.Background()
	email := "account-" + randID(t)[:8] + "@example.com"
	var accountID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_tenant (email,name,email_verified_at)
		VALUES ($1,$1,now()) RETURNING id`, email).Scan(&accountID); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_account_member (account_id,user_id,role)
		VALUES ($1,$2,$3)`, accountID, userID, role); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	return accountID
}

func assertSessionAccounts(t *testing.T, st *postgres.Store, raw string, wantTenant, wantActive *string) {
	t.Helper()
	var tenantID, activeAccountID *string
	if err := st.DB().QueryRow(`
		SELECT tenant_id,active_account_id FROM devradar_session WHERE id=$1`,
		authn.HashToken(raw)).Scan(&tenantID, &activeAccountID); err != nil {
		t.Fatalf("read session accounts: %v", err)
	}
	if !equalOptionalString(tenantID, wantTenant) || !equalOptionalString(activeAccountID, wantActive) {
		t.Fatalf("session tenant/active = %v/%v, want %v/%v",
			tenantID, activeAccountID, wantTenant, wantActive)
	}
}

func equalOptionalString(got, want *string) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}
	return *got == *want
}

type identityResolution struct {
	userID    string
	accountID string
	err       error
}

func startConcurrentIdentityResolutions(
	st *postgres.Store,
	identities []account.VerifiedIdentity,
) <-chan identityResolution {
	start := make(chan struct{})
	results := make(chan identityResolution, len(identities))
	var ready sync.WaitGroup
	ready.Add(len(identities))
	for _, identity := range identities {
		go func() {
			ready.Done()
			<-start
			user, acct, err := st.ResolveDirectIdentity(context.Background(), identity)
			result := identityResolution{err: err}
			if user != nil {
				result.userID = user.ID
			}
			if acct != nil {
				result.accountID = acct.ID
			}
			results <- result
		}()
	}
	ready.Wait()
	close(start)
	return results
}

func collectIdentityResolutions(
	t *testing.T,
	results <-chan identityResolution,
	want int,
) []identityResolution {
	t.Helper()
	resolved := make([]identityResolution, 0, want)
	for range want {
		select {
		case result := <-results:
			if result.err != nil {
				t.Fatalf("concurrent identity resolution: %v", result.err)
			}
			if result.userID == "" || result.accountID == "" {
				t.Fatalf("concurrent identity resolution returned empty IDs: %#v", result)
			}
			resolved = append(resolved, result)
		case <-time.After(10 * time.Second):
			t.Fatal("timed out collecting concurrent identity resolution")
		}
	}
	return resolved
}

func assertSameResolvedIdentity(t *testing.T, resolved []identityResolution) {
	t.Helper()
	for i := 1; i < len(resolved); i++ {
		if resolved[i].userID != resolved[0].userID || resolved[i].accountID != resolved[0].accountID {
			t.Fatalf("resolution %d = %s/%s, want authoritative %s/%s",
				i, resolved[i].userID, resolved[i].accountID,
				resolved[0].userID, resolved[0].accountID)
		}
	}
}

func waitForPostgresBlockers(
	ctx context.Context,
	db *sql.DB,
	holderPID, want int,
	timeout time.Duration,
) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var blocked int
		err := db.QueryRowContext(ctx, `
			SELECT count(*) FROM pg_stat_activity
			WHERE $1=ANY(pg_blocking_pids(pid))`, holderPID).Scan(&blocked)
		if err == nil && blocked >= want {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
	return false
}

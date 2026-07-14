package middleware_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/authn"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
)

func TestAccessContextSeparatesBrowserUserAndAccount(t *testing.T) {
	st := testStore(t)
	user, acct, raw := seedAccessSession(t, st)

	var gotUser *account.User
	var gotAccess *account.Access
	var gotAccount *account.Account
	var gotActor account.Actor
	handler := middleware.RequireUser(st, "/")(
		middleware.RequireAccount(st, "/accounts")(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotUser = middleware.UserFromContext(r.Context())
				gotAccess = middleware.AccessFromContext(r.Context())
				gotAccount = middleware.AccountFromContext(r.Context())
				gotActor = middleware.ActorFromContext(r.Context())
				w.WriteHeader(http.StatusNoContent)
			}),
		),
	)

	req := httptest.NewRequest(http.MethodGet, "/overview", nil)
	req.AddCookie(sessionCookie(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("access middleware status = %d, want 204", rec.Code)
	}
	if gotUser == nil || gotUser.ID != user.ID {
		t.Fatalf("user context = %#v, want %s", gotUser, user.ID)
	}
	if gotAccess == nil || gotAccess.Actor.ID != user.ID || gotAccess.Account.ID != acct.ID {
		t.Fatalf("access context = %#v, want user/account %s/%s", gotAccess, user.ID, acct.ID)
	}
	if gotAccount == nil || gotAccount.ID != acct.ID {
		t.Fatalf("account context = %#v, want %s", gotAccount, acct.ID)
	}
	if gotActor.Kind != account.ActorUser || gotActor.UserID != user.ID || gotActor.APITokenID != "" {
		t.Fatalf("actor context = %#v, want user %s", gotActor, user.ID)
	}
	if gotActor.UserID == gotAccount.ID {
		t.Fatal("browser actor user ID must differ from account ID")
	}
}

func TestSession_RevokedMembershipRedirectsUnavailableWithoutSwitching(t *testing.T) {
	st := testStore(t)
	user, selected, raw := seedAccessSession(t, st)
	other := seedAccountMembership(t, st, user.ID)
	if _, err := st.DB().ExecContext(context.Background(), `
		UPDATE devradar_account_member SET revoked_at=now()
		WHERE account_id=$1 AND user_id=$2`, selected.ID, user.ID); err != nil {
		t.Fatalf("revoke selected membership: %v", err)
	}

	called := false
	handler := middleware.RequireUser(st, "/")(
		middleware.RequireAccount(st, "/accounts")(
			http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }),
		),
	)
	req := httptest.NewRequest(http.MethodGet, "/overview", nil)
	req.AddCookie(sessionCookie(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if called {
		t.Fatal("revoked membership reached account handler")
	}
	if got := rec.Header().Get("Location"); got != "/accounts?error=unavailable" {
		t.Fatalf("revoked membership redirect = %q, want unavailable chooser", got)
	}
	if strings.Contains(rec.Body.String(), selected.ID) || strings.Contains(rec.Body.String(), other.ID) {
		t.Fatal("revoked selection response leaked an account identifier")
	}
	session, err := st.ValidateSession(context.Background(), raw)
	if err != nil {
		t.Fatalf("revoked membership destroyed user session: %v", err)
	}
	if session.ActiveAccountID == nil || *session.ActiveAccountID != selected.ID {
		t.Fatalf("revoked selection silently changed active account: %#v", session.ActiveAccountID)
	}
}

func TestSession_LegacyAccountReconcilesMissingCompatibilityMembership(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	email := "legacy-middleware-" + uniqueSuffix(t) + "@example.com"
	var accountID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`, email).Scan(&accountID); err != nil {
		t.Fatalf("seed legacy account: %v", err)
	}
	if err := st.ReconcileLegacyAccount(ctx, accountID); err != nil {
		t.Fatalf("seed legacy ownership: %v", err)
	}
	var userID string
	if err := st.DB().QueryRowContext(ctx, `
		SELECT id FROM devradar_user WHERE legacy_tenant_id=$1`, accountID).Scan(&userID); err != nil {
		t.Fatalf("read legacy user: %v", err)
	}
	raw, err := st.CreateSession(ctx, userID, &accountID, time.Hour)
	if err != nil {
		t.Fatalf("create legacy session: %v", err)
	}
	if _, err := st.DB().ExecContext(context.Background(), `
		DELETE FROM devradar_account_member WHERE account_id=$1 AND user_id=$2`,
		accountID, userID); err != nil {
		t.Fatalf("remove compatibility membership: %v", err)
	}

	handler := middleware.RequireUser(st, "/")(
		middleware.RequireAccount(st, "/accounts")(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				access := middleware.AccessFromContext(r.Context())
				if access == nil || access.Account.ID != accountID || access.Membership.Role != account.RoleAdmin {
					t.Fatalf("reconciled access = %#v, want legacy admin for %s", access, accountID)
				}
				w.WriteHeader(http.StatusNoContent)
			}),
		),
	)
	req := httptest.NewRequest(http.MethodGet, "/overview", nil)
	req.AddCookie(sessionCookie(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("legacy reconciliation status = %d, want 204", rec.Code)
	}
}

func TestSession_SuspendedUserClearsSession(t *testing.T) {
	st := testStore(t)
	user, _, raw := seedAccessSession(t, st)
	if _, err := st.DB().ExecContext(context.Background(), `
		UPDATE devradar_user SET status='suspended' WHERE id=$1`, user.ID); err != nil {
		t.Fatalf("suspend user: %v", err)
	}

	handler := middleware.RequireUser(st, "/")(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("suspended user reached handler")
		}),
	)
	req := httptest.NewRequest(http.MethodGet, "/accounts", nil)
	req.AddCookie(sessionCookie(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Location"); got != "/?error=suspended" {
		t.Fatalf("suspended user redirect = %q, want suspended login", got)
	}
	if !clearedSessionCookie(rec.Result().Cookies()) {
		t.Fatal("suspended user response did not clear session cookie")
	}
	if _, err := st.ValidateSession(context.Background(), raw); !errors.Is(err, postgres.ErrSessionInvalid) {
		t.Fatalf("suspended user persisted session error = %v, want ErrSessionInvalid", err)
	}
}

func TestSession_SuspendedAccountPreservesUserSession(t *testing.T) {
	st := testStore(t)
	_, acct, raw := seedAccessSession(t, st)
	if _, err := st.DB().ExecContext(context.Background(), `
		UPDATE devradar_tenant SET status='suspended' WHERE id=$1`, acct.ID); err != nil {
		t.Fatalf("suspend account: %v", err)
	}

	handler := middleware.RequireUser(st, "/")(
		middleware.RequireAccount(st, "/accounts")(
			http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("suspended account reached handler")
			}),
		),
	)
	req := httptest.NewRequest(http.MethodGet, "/overview", nil)
	req.AddCookie(sessionCookie(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Location"); got != "/accounts?error=unavailable" {
		t.Fatalf("suspended account redirect = %q, want unavailable chooser", got)
	}
	if clearedSessionCookie(rec.Result().Cookies()) {
		t.Fatal("suspended account cleared the user session cookie")
	}
	if _, err := st.ValidateSession(context.Background(), raw); err != nil {
		t.Fatalf("suspended account destroyed user session: %v", err)
	}
}

func TestAdmin_UsesActorEmailWithoutActiveAccount(t *testing.T) {
	st := testStore(t)
	user, acct, _ := seedAccessSession(t, st)
	raw, err := st.CreateSession(context.Background(), user.ID, nil, time.Hour)
	if err != nil {
		t.Fatalf("create chooser session: %v", err)
	}
	accountEmail := "account-admin-" + uniqueSuffix(t) + "@example.com"
	if _, err := st.DB().ExecContext(context.Background(), `
		UPDATE devradar_tenant SET email=$2 WHERE id=$1`, acct.ID, accountEmail); err != nil {
		t.Fatalf("change compatibility account email: %v", err)
	}

	request := func() int {
		handler := middleware.RequirePlatformAdmin(st)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got := middleware.UserFromContext(r.Context())
			if got == nil || got.ID != user.ID || middleware.AccountFromContext(r.Context()) != nil {
				t.Fatalf("platform admin context user/account = %#v/%#v", got, middleware.AccountFromContext(r.Context()))
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		req.AddCookie(sessionCookie(raw))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	t.Setenv("DEVRADAR_ADMIN_USERS", accountEmail)
	if got := request(); got != http.StatusNotFound {
		t.Fatalf("account email allowlist status = %d, want 404", got)
	}
	t.Setenv("DEVRADAR_ADMIN_USERS", user.Email)
	if got := request(); got != http.StatusNoContent {
		t.Fatalf("actor email allowlist status = %d, want 204", got)
	}
}

func TestAccessContextAPITokenHasOnlyAccountAndTokenActor(t *testing.T) {
	st := testStore(t)
	_, acct, _ := seedAccessSession(t, st)
	raw, err := authn.NewToken("dr_")
	if err != nil {
		t.Fatalf("generate api token: %v", err)
	}
	if _, err := st.DB().ExecContext(context.Background(), `
		INSERT INTO devradar_api_token (tenant_id,name,token_hash,expires_at)
		VALUES ($1,'ci',$2,now()+interval '1 hour')`, acct.ID, authn.HashToken(raw)); err != nil {
		t.Fatalf("seed api token: %v", err)
	}

	handler := middleware.RequireAPIToken(st)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccount := middleware.AccountFromContext(r.Context())
		gotActor := middleware.ActorFromContext(r.Context())
		if gotAccount == nil || gotAccount.ID != acct.ID {
			t.Fatalf("api account context = %#v, want %s", gotAccount, acct.ID)
		}
		if gotActor.Kind != account.ActorAPIToken || gotActor.APITokenID == "" || gotActor.UserID != "" {
			t.Fatalf("api actor context = %#v, want token-only actor", gotActor)
		}
		if middleware.UserFromContext(r.Context()) != nil || middleware.AccessFromContext(r.Context()) != nil {
			t.Fatal("api token inherited a human user or membership")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/v1/images", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("api token middleware status = %d, want 204", rec.Code)
	}
}

func testStore(t *testing.T) *postgres.Store {
	t.Helper()
	st, err := postgres.NewFromEnv(context.Background())
	if err != nil {
		if os.Getenv("DATABASE_URL") != "" {
			t.Fatalf("connect configured integration database: %v", err)
		}
		t.Skipf("skipping (no database): %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func seedAccessSession(t *testing.T, st *postgres.Store) (*account.User, *account.Account, string) {
	t.Helper()
	email := "middleware-" + uniqueSuffix(t) + "@example.com"
	user, acct, err := st.ResolveDirectIdentity(context.Background(), account.VerifiedIdentity{
		Provider: "magiclink", Subject: email, Email: email,
	})
	if err != nil {
		t.Fatalf("resolve identity: %v", err)
	}
	if acct == nil {
		t.Fatal("direct identity has no account")
	}
	raw, err := st.CreateSession(context.Background(), user.ID, &acct.ID, time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return user, acct, raw
}

func seedAccountMembership(t *testing.T, st *postgres.Store, userID string) *account.Account {
	t.Helper()
	email := "account-" + uniqueSuffix(t) + "@example.com"
	var accountID string
	if err := st.DB().QueryRowContext(context.Background(), `
		INSERT INTO devradar_tenant (email,name) VALUES ($1,$1) RETURNING id`, email).Scan(&accountID); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	if _, err := st.DB().ExecContext(context.Background(), `
		INSERT INTO devradar_account_member (account_id,user_id,role,accepted_at)
		VALUES ($1,$2,'reader',now())`, accountID, userID); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	acct, err := st.GetAccount(context.Background(), accountID)
	if err != nil {
		t.Fatalf("get seeded account: %v", err)
	}
	return acct
}

func uniqueSuffix(t *testing.T) string {
	t.Helper()
	raw, err := authn.NewToken("")
	if err != nil {
		t.Fatalf("generate unique suffix: %v", err)
	}
	return raw[:12]
}

func sessionCookie(raw string) *http.Cookie {
	return &http.Cookie{Name: middleware.SessionCookieName(), Value: raw}
}

func clearedSessionCookie(cookies []*http.Cookie) bool {
	for _, cookie := range cookies {
		if cookie.Name == middleware.SessionCookieName() && cookie.MaxAge < 0 {
			return true
		}
	}
	return false
}

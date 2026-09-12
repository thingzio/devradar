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

package server_test

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/authn"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/gcs"
	"github.com/thingzio/devradar/pkg/middleware"
	"github.com/thingzio/devradar/pkg/oauth"
	"github.com/thingzio/devradar/pkg/server"
)

// fakeOAuth is an in-memory OAuthProvider. Exchange returns id/err verbatim so a
// test can drive the happy path, the unverified-email path, or a hard failure
// without any network.
type fakeOAuth struct {
	id  *oauth.Identity
	err error
}

func (f fakeOAuth) AuthCodeURL(state string) string {
	return "https://github.test/login/oauth/authorize?state=" + state
}
func (f fakeOAuth) Exchange(_ context.Context, _ string) (*oauth.Identity, error) {
	return f.id, f.err
}

// oauthServer builds a server wired with the given fake OAuth provider.
func oauthServer(t *testing.T, p server.OAuthProvider) (*server.Server, *postgres.Store) {
	t.Helper()
	_, st := testServer(t)
	srv := server.New(st, gcs.LocalStore{Dir: t.TempDir()}, nil, p, nil, server.Options{Version: "test"})
	return srv, st
}

// startFlow issues GET /auth/github and returns the state cookie the server set.
func startFlow(t *testing.T, h http.Handler) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/github", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("start: status = %d, want 302", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == middleware.OAuthStateCookieName() {
			return c
		}
	}
	t.Fatal("start did not set an oauth state cookie")
	return nil
}

// TestGitHubOAuth_LandingButton: when OAuth is configured the landing page shows
// the GitHub sign-in link (and the template renders without error).
func TestGitHubOAuth_LandingButton(t *testing.T) {
	srv, _ := oauthServer(t, fakeOAuth{})
	h := srv.Handler()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("landing status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `href="/auth/github"`) {
		t.Error("landing should show the GitHub sign-in button when OAuth is configured")
	}
}

// TestGitHubOAuth_HappyPath: a verified GitHub identity signs in, creating a
// tenant and a session cookie, landing on /overview.
func TestGitHubOAuth_HappyPath(t *testing.T) {
	srv, st := oauthServer(t, fakeOAuth{id: &oauth.Identity{
		Provider: "github", Subject: "12345", Email: "gh@example.com",
		AvatarURL: "https://avatars.githubusercontent.com/u/12345?v=4",
	}})
	h := srv.Handler()

	state := startFlow(t, h)
	req := httptest.NewRequest(http.MethodGet,
		"/auth/github/callback?state="+state.Value+"&code=abc", nil)
	req.AddCookie(state)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/overview" {
		t.Fatalf("callback: status=%d loc=%q, want 302 /overview", rec.Code, rec.Header().Get("Location"))
	}
	var gotSession bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == middleware.SessionCookieName() && c.Value != "" {
			gotSession = true
		}
	}
	if !gotSession {
		t.Error("callback should mint a session cookie")
	}

	// The GitHub avatar is person state and is persisted on the user.
	var avatar string
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT avatar_url FROM devradar_user WHERE email='gh@example.com'`).Scan(&avatar); err != nil {
		t.Fatalf("query avatar: %v", err)
	}
	if avatar != "https://avatars.githubusercontent.com/u/12345?v=4" {
		t.Errorf("avatar_url = %q, want the GitHub avatar", avatar)
	}
}

func TestGitHubOAuth_MemberlessUserRedirectsToAccounts(t *testing.T) {
	suffix, err := authn.NewToken("")
	if err != nil {
		t.Fatalf("generate identity suffix: %v", err)
	}
	email := "memberless-github-" + suffix[:8] + "@example.com"
	srv, st := oauthServer(t, fakeOAuth{id: &oauth.Identity{
		Provider: "github", Subject: "memberless-" + suffix[8:16], Email: email,
	}})
	ctx := context.Background()
	var userID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_user (email,email_verified_at)
		VALUES ($1,now()) RETURNING id`, email).Scan(&userID); err != nil {
		t.Fatalf("seed memberless user: %v", err)
	}
	h := srv.Handler()
	state := startFlow(t, h)
	req := httptest.NewRequest(http.MethodGet,
		"/auth/github/callback?state="+state.Value+"&code=abc", nil)
	req.AddCookie(state)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Location"); got != "/accounts" {
		t.Fatalf("memberless callback redirect = %q, want /accounts", got)
	}
	var sessionRaw string
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == middleware.SessionCookieName() {
			sessionRaw = cookie.Value
		}
	}
	if sessionRaw == "" {
		t.Fatal("memberless callback did not create user session")
	}
	session, err := st.ValidateSession(ctx, sessionRaw)
	if err != nil {
		t.Fatalf("validate memberless session: %v", err)
	}
	if session.User.ID != userID || session.ActiveAccountID != nil {
		t.Fatalf("memberless session = %#v, want user %s with nil account", session, userID)
	}
}

// TestGitHubOAuth_StateMismatch: a callback whose state does not match the cookie
// is rejected (CSRF defense) — no session minted.
func TestGitHubOAuth_StateMismatch(t *testing.T) {
	srv, _ := oauthServer(t, fakeOAuth{id: &oauth.Identity{
		Provider: "github", Subject: "1", Email: "x@example.com",
	}})
	h := srv.Handler()

	state := startFlow(t, h)
	req := httptest.NewRequest(http.MethodGet,
		"/auth/github/callback?state=WRONG&code=abc", nil)
	req.AddCookie(state)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=oauth") {
		t.Errorf("state mismatch redirect = %q, want ?error=oauth", loc)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == middleware.SessionCookieName() && c.Value != "" {
			t.Error("no session should be minted on state mismatch")
		}
	}
}

// TestGitHubOAuth_MissingStateCookie: a callback with no state cookie at all
// (e.g. a forged link) is rejected.
func TestGitHubOAuth_MissingStateCookie(t *testing.T) {
	srv, _ := oauthServer(t, fakeOAuth{id: &oauth.Identity{Provider: "github", Subject: "1", Email: "x@x.com"}})
	h := srv.Handler()
	req := httptest.NewRequest(http.MethodGet, "/auth/github/callback?state=abc&code=abc", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=oauth") {
		t.Errorf("missing state cookie redirect = %q, want ?error=oauth", loc)
	}
}

// TestGitHubOAuth_Unverified: an unverified-email provider result surfaces the
// specific "unverified" message rather than signing the user in.
func TestGitHubOAuth_Unverified(t *testing.T) {
	srv, _ := oauthServer(t, fakeOAuth{err: oauth.ErrNoVerifiedEmail})
	h := srv.Handler()

	state := startFlow(t, h)
	req := httptest.NewRequest(http.MethodGet,
		"/auth/github/callback?state="+state.Value+"&code=abc", nil)
	req.AddCookie(state)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=unverified") {
		t.Errorf("unverified redirect = %q, want ?error=unverified", loc)
	}
}

// TestGitHubOAuth_UnifiesWithMagicLink: signing in with GitHub whose verified
// email matches an existing magic-link user resolves to the same user and
// account membership rather than creating a second account.
func TestGitHubOAuth_UnifiesWithMagicLink(t *testing.T) {
	suffix, err := authn.NewToken("")
	if err != nil {
		t.Fatalf("generate identity suffix: %v", err)
	}
	email := "same-" + suffix[:8] + "@example.com"
	subject := "unify-" + suffix[8:16]
	srv, st := oauthServer(t, fakeOAuth{id: &oauth.Identity{
		Provider: "github", Subject: subject, Email: email,
	}})
	h := srv.Handler()
	ctx := context.Background()

	// Pre-existing user and account created via the magic-link flow.
	existingUser, existingAccount, err := st.ResolveDirectIdentity(ctx, account.VerifiedIdentity{
		Provider: "magiclink", Subject: email, Email: email,
	})
	if err != nil {
		t.Fatalf("seed magic-link account: %v", err)
	}
	if existingAccount == nil {
		t.Fatal("seed magic-link account: no account")
	}

	state := startFlow(t, h)
	req := httptest.NewRequest(http.MethodGet,
		"/auth/github/callback?state="+state.Value+"&code=abc", nil)
	req.AddCookie(state)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/overview" {
		t.Fatalf("callback: status=%d location=%q, want 302 /overview",
			rec.Code, rec.Header().Get("Location"))
	}

	// The new identity owns the existing user directly. tenant_id is only a
	// legacy compatibility mapping and remains null for additional identities.
	var linkedUser string
	var compatibilityAccount sql.NullString
	var accounts int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT i.user_id,i.tenant_id,
		       (SELECT count(*) FROM devradar_tenant WHERE email=$2)
		FROM devradar_identity i WHERE i.provider='github' AND i.subject=$1`, subject, email).
		Scan(&linkedUser, &compatibilityAccount, &accounts); err != nil {
		t.Fatalf("query identity: %v", err)
	}
	if linkedUser != existingUser.ID || compatibilityAccount.Valid || accounts != 1 {
		t.Errorf("github identity user/compatibility account/account count = %s/%v/%d, want %s/null/1",
			linkedUser, compatibilityAccount, accounts, existingUser.ID)
	}
	access, err := st.GetAccess(ctx, existingUser.ID, existingAccount.ID)
	if err != nil || access.Membership.Role != account.RoleAdmin {
		t.Fatalf("existing account membership = %#v, %v", access, err)
	}
}

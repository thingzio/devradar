package server_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
)

func TestAccountSwitchListsMultipleAccountsAndSelectsWithCSRF(t *testing.T) {
	srv, st := testServer(t)
	h := srv.Handler()
	session, userID, firstAccountID := seedAccountSwitchSession(t, st)
	secondAccountID := seedAdditionalAccount(t, st, userID, account.RoleEditor, "Second workspace")

	csrfCookie, csrfToken := csrfFor(t, h, session, "/accounts")
	get := httptest.NewRequest(http.MethodGet, "/accounts", nil)
	get.AddCookie(session)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, get)
	if getRec.Code != http.StatusOK {
		t.Fatalf("accounts GET = %d: %s", getRec.Code, getRec.Body.String())
	}
	for _, want := range []string{"First workspace", "Second workspace", `action="/accounts/select"`} {
		if !strings.Contains(getRec.Body.String(), want) {
			t.Fatalf("accounts page missing %q: %s", want, getRec.Body.String())
		}
	}

	withoutCSRF := accountFormRequest(http.MethodPost, "/accounts/select", session, nil,
		url.Values{"account_id": {secondAccountID}})
	withoutRec := httptest.NewRecorder()
	h.ServeHTTP(withoutRec, withoutCSRF)
	if withoutRec.Code != http.StatusForbidden {
		t.Fatalf("selection without CSRF = %d, want 403", withoutRec.Code)
	}
	assertSelectedAccount(t, st, session, firstAccountID)

	selectReq := accountFormRequest(http.MethodPost, "/accounts/select", session, csrfCookie,
		url.Values{"account_id": {secondAccountID}, "csrf_token": {csrfToken}})
	selectRec := httptest.NewRecorder()
	h.ServeHTTP(selectRec, selectReq)
	if selectRec.Code != http.StatusSeeOther || selectRec.Header().Get("Location") != "/overview" {
		t.Fatalf("selection = %d location %q, want 303 /overview: %s",
			selectRec.Code, selectRec.Header().Get("Location"), selectRec.Body.String())
	}
	assertSelectedAccount(t, st, session, secondAccountID)
}

func TestAccountSwitchUnavailableDoesNotChangeSelection(t *testing.T) {
	srv, st := testServer(t)
	h := srv.Handler()
	session, userID, activeAccountID := seedAccountSwitchSession(t, st)
	revokedAccountID := seedAdditionalAccount(t, st, userID, account.RoleReader, "Revoked workspace")
	if _, err := st.DB().ExecContext(context.Background(), `
		UPDATE devradar_account_member SET revoked_at=now(),updated_at=now()
		WHERE account_id=$1 AND user_id=$2`, revokedAccountID, userID); err != nil {
		t.Fatalf("revoke selection membership: %v", err)
	}
	unrelatedAccountID, _ := seedTenantToken(t, st)
	csrfCookie, csrfToken := csrfFor(t, h, session, "/accounts")

	for _, accountID := range []string{revokedAccountID, unrelatedAccountID} {
		req := accountFormRequest(http.MethodPost, "/accounts/select", session, csrfCookie,
			url.Values{"account_id": {accountID}, "csrf_token": {csrfToken}})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/accounts?error=unavailable" {
			t.Fatalf("unavailable selection = %d location %q, want chooser: %s",
				rec.Code, rec.Header().Get("Location"), rec.Body.String())
		}
		assertSelectedAccount(t, st, session, activeAccountID)
	}
}

func TestAccountSwitchSelectsFromChooserSession(t *testing.T) {
	srv, st := testServer(t)
	h := srv.Handler()
	_, userID, firstAccountID := seedAccountSwitchSession(t, st)
	secondAccountID := seedAdditionalAccount(t, st, userID, account.RoleReader, "Chooser workspace")
	raw, err := st.CreateSession(context.Background(), userID, nil, time.Hour)
	if err != nil {
		t.Fatalf("create chooser session: %v", err)
	}
	session := &http.Cookie{Name: middleware.SessionCookieName(), Value: raw}
	csrfCookie, csrfToken := csrfFor(t, h, session, "/accounts")
	req := accountFormRequest(http.MethodPost, "/accounts/select", session, csrfCookie,
		url.Values{"account_id": {secondAccountID}, "csrf_token": {csrfToken}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/overview" {
		t.Fatalf("chooser selection = %d location %q: %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	assertSelectedAccount(t, st, session, secondAccountID)
	if firstAccountID == secondAccountID {
		t.Fatal("chooser accounts unexpectedly identical")
	}
}

func TestAccountSwitchCanLeaveNonActiveMembership(t *testing.T) {
	srv, st := testServer(t)
	h := srv.Handler()
	session, userID, activeAccountID := seedAccountSwitchSession(t, st)
	leaveAccountID := seedAdditionalAccount(t, st, userID, account.RoleEditor, "Leave workspace")
	csrfCookie, csrfToken := csrfFor(t, h, session, "/accounts")
	withoutCSRF := accountFormRequest(http.MethodPost, "/accounts/"+leaveAccountID+"/leave", session, nil, nil)
	withoutRec := httptest.NewRecorder()
	h.ServeHTTP(withoutRec, withoutCSRF)
	if withoutRec.Code != http.StatusForbidden {
		t.Fatalf("leave without CSRF = %d, want 403", withoutRec.Code)
	}
	if _, err := st.GetAccess(context.Background(), userID, leaveAccountID); err != nil {
		t.Fatalf("leave without CSRF changed membership: %v", err)
	}

	req := accountFormRequest(http.MethodPost, "/accounts/"+leaveAccountID+"/leave", session, csrfCookie,
		url.Values{"csrf_token": {csrfToken}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/accounts?msg=left" {
		t.Fatalf("leave = %d location %q: %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if _, err := st.GetAccess(context.Background(), userID, leaveAccountID); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("left access = %v, want ErrNotFound", err)
	}
	assertSelectedAccount(t, st, session, activeAccountID)
}

func TestAccountSwitchZeroMembershipGuidance(t *testing.T) {
	srv, st := testServer(t)
	h := srv.Handler()
	var userID string
	if err := st.DB().QueryRowContext(context.Background(), `
		INSERT INTO devradar_user (email,email_verified_at)
		VALUES ($1,now()) RETURNING id`, "memberless-"+randomHex(t, 6)+"@example.com").Scan(&userID); err != nil {
		t.Fatalf("seed memberless user: %v", err)
	}
	raw, err := st.CreateSession(context.Background(), userID, nil, time.Hour)
	if err != nil {
		t.Fatalf("create memberless session: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/accounts", nil)
	req.AddCookie(&http.Cookie{Name: middleware.SessionCookieName(), Value: raw})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Ask an account admin for an invitation") {
		t.Fatalf("memberless page = %d: %s", rec.Code, rec.Body.String())
	}
	for _, forbidden := range []string{"Create account", `action="/accounts/create"`} {
		if strings.Contains(rec.Body.String(), forbidden) {
			t.Fatalf("memberless page exposed %q: %s", forbidden, rec.Body.String())
		}
	}
}

func TestAccountSettingsNameValidationAndAudit(t *testing.T) {
	srv, st := testServer(t)
	h := srv.Handler()
	session, _, accountID := seedAccountSwitchSession(t, st)
	csrfCookie, csrfToken := csrfFor(t, h, session, "/account/settings")

	req := accountFormRequest(http.MethodPost, "/account/settings/name", session, csrfCookie,
		url.Values{"name": {"  Renamed workspace  "}, "csrf_token": {csrfToken}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/account/settings?msg=renamed" {
		t.Fatalf("rename = %d location %q: %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	var name string
	var audits int
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT name,(SELECT count(*) FROM devradar_audit_event
		 WHERE account_id=$1 AND action='account.name.update')
		FROM devradar_tenant WHERE id=$1`, accountID).Scan(&name, &audits); err != nil {
		t.Fatalf("read renamed account: %v", err)
	}
	if name != "Renamed workspace" || audits != 1 {
		t.Fatalf("rename state/audits = %q/%d, want Renamed workspace/1", name, audits)
	}

	invalid := accountFormRequest(http.MethodPost, "/account/settings/name", session, csrfCookie,
		url.Values{"name": {strings.Repeat("界", 81)}, "csrf_token": {csrfToken}})
	invalidRec := httptest.NewRecorder()
	h.ServeHTTP(invalidRec, invalid)
	if invalidRec.Code != http.StatusBadRequest {
		t.Fatalf("invalid rename = %d, want 400: %s", invalidRec.Code, invalidRec.Body.String())
	}
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT count(*) FROM devradar_audit_event
		WHERE account_id=$1 AND action='account.name.update'`, accountID).Scan(&audits); err != nil {
		t.Fatalf("count rename audits: %v", err)
	}
	if audits != 1 {
		t.Fatalf("invalid rename audits = %d, want 1", audits)
	}
}

func TestMembershipUIRoleRevokeAndLastAdmin(t *testing.T) {
	srv, st := testServer(t)
	h := srv.Handler()
	session, adminID, accountID := seedAccountSwitchSession(t, st)
	memberID := seedAdditionalMember(t, st, accountID, account.RoleReader, adminID)
	csrfCookie, csrfToken := csrfFor(t, h, session, "/account/members")

	roleReq := accountFormRequest(http.MethodPost, "/account/members/"+memberID+"/role", session, csrfCookie,
		url.Values{"role": {"editor"}, "csrf_token": {csrfToken}})
	roleRec := httptest.NewRecorder()
	h.ServeHTTP(roleRec, roleReq)
	if roleRec.Code != http.StatusSeeOther {
		t.Fatalf("role change = %d: %s", roleRec.Code, roleRec.Body.String())
	}
	access, err := st.GetAccess(context.Background(), memberID, accountID)
	if err != nil || access.Membership.Role != account.RoleEditor {
		t.Fatalf("changed access = %#v, %v", access, err)
	}

	revokeReq := accountFormRequest(http.MethodPost, "/account/members/"+memberID+"/revoke", session, csrfCookie,
		url.Values{"csrf_token": {csrfToken}})
	revokeRec := httptest.NewRecorder()
	h.ServeHTTP(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusSeeOther {
		t.Fatalf("revoke = %d: %s", revokeRec.Code, revokeRec.Body.String())
	}
	assertSelectedAccount(t, st, session, accountID)

	leaveReq := accountFormRequest(http.MethodPost, "/accounts/"+accountID+"/leave", session, csrfCookie,
		url.Values{"csrf_token": {csrfToken}})
	leaveRec := httptest.NewRecorder()
	h.ServeHTTP(leaveRec, leaveReq)
	if leaveRec.Code != http.StatusConflict || !strings.Contains(leaveRec.Body.String(), "another admin") {
		t.Fatalf("last admin leave = %d, want 409 guidance: %s", leaveRec.Code, leaveRec.Body.String())
	}
}

func TestMembershipUISelfMutationRedirectsRemainUsable(t *testing.T) {
	for _, tc := range []struct {
		name, pathSuffix string
		form             url.Values
		wantLocation     string
		cleared          bool
	}{
		{"demote", "/role", url.Values{"role": {"editor"}}, "/overview", false},
		{"revoke", "/revoke", nil, "/accounts?msg=left", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, st := testServer(t)
			h := srv.Handler()
			session, adminID, accountID := seedAccountSwitchSession(t, st)
			_ = seedAdditionalMember(t, st, accountID, account.RoleAdmin, adminID)
			csrfCookie, csrfToken := csrfFor(t, h, session, "/account/members")
			form := tc.form
			if form == nil {
				form = make(url.Values)
			}
			form.Set("csrf_token", csrfToken)
			req := accountFormRequest(http.MethodPost,
				"/account/members/"+adminID+tc.pathSuffix, session, csrfCookie, form)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != tc.wantLocation {
				t.Fatalf("self %s = %d location %q, want 303 %s: %s",
					tc.name, rec.Code, rec.Header().Get("Location"), tc.wantLocation, rec.Body.String())
			}
			if tc.cleared {
				assertNoSelectedAccount(t, st, session)
			} else {
				assertSelectedAccount(t, st, session, accountID)
			}
		})
	}
}

func TestAccountLeaveSelectedClearsSessionAndAvoidsUnavailableBounce(t *testing.T) {
	srv, st := testServer(t)
	h := srv.Handler()
	session, userID, accountID := seedAccountSwitchSession(t, st)
	_ = seedAdditionalMember(t, st, accountID, account.RoleAdmin, userID)
	if _, err := st.DB().ExecContext(context.Background(), `
		UPDATE devradar_account_member SET role='editor',updated_at=now()
		WHERE account_id=$1 AND user_id=$2`, accountID, userID); err != nil {
		t.Fatalf("make leaving user editor: %v", err)
	}
	csrfCookie, csrfToken := csrfFor(t, h, session, "/accounts")
	req := accountFormRequest(http.MethodPost, "/accounts/"+accountID+"/leave", session, csrfCookie,
		url.Values{"csrf_token": {csrfToken}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/accounts?msg=left" {
		t.Fatalf("selected leave = %d location %q: %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	assertNoSelectedAccount(t, st, session)

	overview := httptest.NewRequest(http.MethodGet, "/overview", nil)
	overview.AddCookie(session)
	overviewRec := httptest.NewRecorder()
	h.ServeHTTP(overviewRec, overview)
	if overviewRec.Code != http.StatusFound || overviewRec.Header().Get("Location") != "/accounts" {
		t.Fatalf("overview after leave = %d location %q, want chooser without unavailable bounce",
			overviewRec.Code, overviewRec.Header().Get("Location"))
	}
}

func TestAccountStaleSessionAfterCleanupFailureFailsClosed(t *testing.T) {
	srv, st := testServer(t)
	h := srv.Handler()
	session, userID, accountID := seedAccountSwitchSession(t, st)
	_ = seedAdditionalMember(t, st, accountID, account.RoleAdmin, userID)
	if _, err := st.DB().ExecContext(context.Background(), `
		UPDATE devradar_account_member SET role='editor',updated_at=now()
		WHERE account_id=$1 AND user_id=$2`, accountID, userID); err != nil {
		t.Fatalf("make stale-session user editor: %v", err)
	}
	if err := st.LeaveAccountAudited(context.Background(), accountID,
		account.Actor{Kind: account.ActorUser, UserID: userID}, "cleanup-failure-test"); err != nil {
		t.Fatalf("leave without cleanup: %v", err)
	}
	assertSelectedAccount(t, st, session, accountID)

	req := httptest.NewRequest(http.MethodGet, "/overview", nil)
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/accounts?error=unavailable" {
		t.Fatalf("stale revoked selection = %d location %q, want fail-closed chooser",
			rec.Code, rec.Header().Get("Location"))
	}
}

func TestAccountMalformedIDsFailClosed(t *testing.T) {
	srv, st := testServer(t)
	h := srv.Handler()
	session, _, _ := seedAccountSwitchSession(t, st)
	csrfCookie, csrfToken := csrfFor(t, h, session, "/account/members")
	tests := []struct {
		path string
		form url.Values
		code int
		loc  string
	}{
		{"/accounts/select", url.Values{"account_id": {"not-a-uuid"}}, http.StatusSeeOther, "/accounts?error=unavailable"},
		{"/accounts/not-a-uuid/leave", nil, http.StatusNotFound, ""},
		{"/account/members/not-a-uuid/role", url.Values{"role": {"reader"}}, http.StatusNotFound, ""},
		{"/account/members/not-a-uuid/revoke", nil, http.StatusNotFound, ""},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			form := tc.form
			if form == nil {
				form = make(url.Values)
			}
			form.Set("csrf_token", csrfToken)
			req := accountFormRequest(http.MethodPost, tc.path, session, csrfCookie, form)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.code || rec.Header().Get("Location") != tc.loc {
				t.Fatalf("malformed ID = %d location %q, want %d/%q: %s",
					rec.Code, rec.Header().Get("Location"), tc.code, tc.loc, rec.Body.String())
			}
		})
	}
}

func seedAccountSwitchSession(t *testing.T, st *postgres.Store) (*http.Cookie, string, string) {
	t.Helper()
	accountID, _ := seedTenantToken(t, st)
	userID := seedLegacyUser(t, st, accountID)
	if _, err := st.DB().ExecContext(context.Background(), `
		UPDATE devradar_tenant SET name='First workspace' WHERE id=$1`, accountID); err != nil {
		t.Fatalf("name first account: %v", err)
	}
	raw, err := st.CreateSession(context.Background(), userID, &accountID, time.Hour)
	if err != nil {
		t.Fatalf("create account switch session: %v", err)
	}
	return &http.Cookie{Name: middleware.SessionCookieName(), Value: raw}, userID, accountID
}

func seedAdditionalAccount(t *testing.T, st *postgres.Store, userID string, role account.Role, name string) string {
	t.Helper()
	var accountID string
	if err := st.DB().QueryRowContext(context.Background(), `
		INSERT INTO devradar_tenant (email,name) VALUES ($1,$2) RETURNING id`,
		"account-"+randomHex(t, 6)+"@example.com", name).Scan(&accountID); err != nil {
		t.Fatalf("seed additional account: %v", err)
	}
	if _, err := st.DB().ExecContext(context.Background(), `
		INSERT INTO devradar_account_member (account_id,user_id,role)
		VALUES ($1,$2,$3)`, accountID, userID, role); err != nil {
		t.Fatalf("seed additional membership: %v", err)
	}
	return accountID
}

func seedAdditionalMember(t *testing.T, st *postgres.Store, accountID string, role account.Role, creatorID string) string {
	t.Helper()
	var userID string
	if err := st.DB().QueryRowContext(context.Background(), `
		INSERT INTO devradar_user (email,email_verified_at)
		VALUES ($1,now()) RETURNING id`, "ui-member-"+randomHex(t, 6)+"@example.com").Scan(&userID); err != nil {
		t.Fatalf("seed UI member: %v", err)
	}
	if _, err := st.DB().ExecContext(context.Background(), `
		INSERT INTO devradar_account_member (account_id,user_id,role,created_by_user_id)
		VALUES ($1,$2,$3,$4)`, accountID, userID, role, creatorID); err != nil {
		t.Fatalf("seed UI membership: %v", err)
	}
	return userID
}

func accountFormRequest(method, path string, session, csrfCookie *http.Cookie, form url.Values) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	if csrfCookie != nil {
		req.AddCookie(csrfCookie)
	}
	return req
}

func assertSelectedAccount(t *testing.T, st *postgres.Store, session *http.Cookie, want string) {
	t.Helper()
	got, err := st.ValidateSession(context.Background(), session.Value)
	if err != nil {
		t.Fatalf("validate selected session: %v", err)
	}
	if got.ActiveAccountID == nil || *got.ActiveAccountID != want {
		t.Fatalf("selected account = %v, want %s", got.ActiveAccountID, want)
	}
}

func assertNoSelectedAccount(t *testing.T, st *postgres.Store, session *http.Cookie) {
	t.Helper()
	got, err := st.ValidateSession(context.Background(), session.Value)
	if err != nil {
		t.Fatalf("validate chooser session: %v", err)
	}
	if got.ActiveAccountID != nil {
		t.Fatalf("selected account = %s, want nil", *got.ActiveAccountID)
	}
}

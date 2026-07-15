package server_test

import (
	"context"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
	"github.com/thingzio/devradar/pkg/ratelimit"
	"github.com/thingzio/devradar/pkg/secretbox"
)

var invitationKey = []byte("0123456789abcdef0123456789abcdef")

func enableInvitationUI(t *testing.T) {
	t.Helper()
	t.Setenv("DEVRADAR_ACCOUNT_SHARING_ENABLED", "true")
	t.Setenv("DEVRADAR_DELIVERY_KEY", base64.StdEncoding.EncodeToString(invitationKey))
	t.Setenv("DEVRADAR_INVITATION_RATE_ACCOUNT", "20")
	t.Setenv("DEVRADAR_INVITATION_RATE_RECIPIENT", "5")
}

func TestInvitationRoutesAndControlsAreFeatureGated(t *testing.T) {
	t.Setenv("DEVRADAR_ACCOUNT_SHARING_ENABLED", "false")
	srv, st := testServer(t)
	session, _, _ := seedAccountSwitchSession(t, st)
	h := srv.Handler()

	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/invitations/not-a-token", nil),
		httptest.NewRequest(http.MethodGet, "/account-invitations/00000000-0000-0000-0000-000000000000", nil),
		accountFormRequest(http.MethodPost, "/account/invitations", session, nil, url.Values{"email": {"x@example.com"}, "role": {"reader"}}),
	} {
		if req.Method == http.MethodPost {
			req.AddCookie(session)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("disabled %s %s = %d, want 404", req.Method, req.URL.Path, rec.Code)
		}
		if strings.HasPrefix(req.URL.Path, "/account-invitations/") {
			assertInvitationResponseHeaders(t, rec)
		}
	}
	get := httptest.NewRequest(http.MethodGet, "/account/members", nil)
	get.AddCookie(session)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, get)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "Invite collaborator") {
		t.Fatalf("disabled members page = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAccountMembersInvitationCreateRefreshResendAndRevoke(t *testing.T) {
	enableInvitationUI(t)
	srv, st := testServer(t)
	session, _, accountID := seedAccountSwitchSession(t, st)
	h := srv.Handler()
	csrfCookie, csrfToken := csrfFor(t, h, session, "/account/members")
	email := "http-invite-" + randomHex(t, 6) + "@example.com"

	without := accountFormRequest(http.MethodPost, "/account/invitations", session, nil,
		url.Values{"email": {email}, "role": {"reader"}})
	withoutRec := httptest.NewRecorder()
	h.ServeHTTP(withoutRec, without)
	if withoutRec.Code != http.StatusForbidden {
		t.Fatalf("create without CSRF = %d", withoutRec.Code)
	}

	create := accountFormRequest(http.MethodPost, "/account/invitations", session, csrfCookie,
		url.Values{"email": {email}, "role": {"reader"}, "csrf_token": {csrfToken}})
	createRec := httptest.NewRecorder()
	h.ServeHTTP(createRec, create)
	if createRec.Code != http.StatusSeeOther || createRec.Header().Get("Location") != "/account/members?msg=invited" {
		t.Fatalf("create = %d location %q: %s", createRec.Code, createRec.Header().Get("Location"), createRec.Body.String())
	}
	var invitationID string
	if err := st.DB().QueryRow(`SELECT id FROM devradar_account_invitation WHERE account_id=$1 AND normalized_email=$2`, accountID, email).Scan(&invitationID); err != nil {
		t.Fatal(err)
	}

	role := accountFormRequest(http.MethodPost, "/account/invitations/"+invitationID+"/role", session, csrfCookie,
		url.Values{"role": {"editor"}, "csrf_token": {csrfToken}})
	roleRec := httptest.NewRecorder()
	h.ServeHTTP(roleRec, role)
	if roleRec.Code != http.StatusSeeOther {
		t.Fatalf("pending role change = %d: %s", roleRec.Code, roleRec.Body.String())
	}
	var gotRole string
	var version int
	if err := st.DB().QueryRow(`SELECT role,token_version FROM devradar_account_invitation WHERE id=$1`, invitationID).Scan(&gotRole, &version); err != nil {
		t.Fatal(err)
	}
	if gotRole != "editor" || version != 2 {
		t.Fatalf("pending role/version = %s/%d", gotRole, version)
	}

	resend := accountFormRequest(http.MethodPost, "/account/invitations/"+invitationID+"/resend", session, csrfCookie,
		url.Values{"csrf_token": {csrfToken}})
	resendRec := httptest.NewRecorder()
	h.ServeHTTP(resendRec, resend)
	if resendRec.Code != http.StatusTooManyRequests {
		t.Fatalf("immediate resend = %d, want 429: %s", resendRec.Code, resendRec.Body.String())
	}

	revoke := accountFormRequest(http.MethodPost, "/account/invitations/"+invitationID+"/revoke", session, csrfCookie,
		url.Values{"csrf_token": {csrfToken}})
	revokeRec := httptest.NewRecorder()
	h.ServeHTTP(revokeRec, revoke)
	if revokeRec.Code != http.StatusSeeOther {
		t.Fatalf("revoke = %d: %s", revokeRec.Code, revokeRec.Body.String())
	}
	var pending int
	if err := st.DB().QueryRow(`SELECT count(*) FROM devradar_account_invitation WHERE id=$1 AND revoked_at IS NULL`, invitationID).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("pending after revoke = %d, %v", pending, err)
	}
}

func TestInvitationCreateWithDifferentRoleUsesRoleChange(t *testing.T) {
	enableInvitationUI(t)
	srv, st := testServer(t)
	session, _, accountID := seedAccountSwitchSession(t, st)
	h := srv.Handler()
	csrfCookie, csrfToken := csrfFor(t, h, session, "/account/members")
	email := "http-role-change-" + randomHex(t, 6) + "@example.com"
	create := func(role string) *httptest.ResponseRecorder {
		t.Helper()
		req := accountFormRequest(http.MethodPost, "/account/invitations", session, csrfCookie,
			url.Values{"email": {email}, "role": {role}, "csrf_token": {csrfToken}})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := create("reader"); rec.Code != http.StatusSeeOther {
		t.Fatalf("initial create = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := create("editor"); rec.Code != http.StatusSeeOther {
		t.Fatalf("different-role create = %d: %s", rec.Code, rec.Body.String())
	}
	var role, action string
	var version int
	if err := st.DB().QueryRow(`
		SELECT i.role,i.token_version,(
			SELECT action FROM devradar_audit_event a
			WHERE a.account_id=i.account_id AND a.target_type='invitation' AND a.target_id=i.id::text
			ORDER BY a.id DESC LIMIT 1)
		FROM devradar_account_invitation i
		WHERE i.account_id=$1 AND i.normalized_email=$2`, accountID, email).
		Scan(&role, &version, &action); err != nil {
		t.Fatal(err)
	}
	if role != "editor" || version != 2 || action != "invitation.role_change" {
		t.Fatalf("different-role create role/version/action = %s/%d/%s", role, version, action)
	}
}

func TestConcurrentIdenticalInvitationCreatesShareMutationAndQuota(t *testing.T) {
	enableInvitationUI(t)
	t.Setenv("DEVRADAR_INVITATION_RATE_ACCOUNT", "1")
	t.Setenv("DEVRADAR_INVITATION_RATE_RECIPIENT", "1")
	srv, st := testServer(t)
	session, _, accountID := seedAccountSwitchSession(t, st)
	h := srv.Handler()
	csrfCookie, csrfToken := csrfFor(t, h, session, "/account/members")
	email := "concurrent-create-" + randomHex(t, 6) + "@example.com"

	blocker, err := st.DB().Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = blocker.Close() })
	blockerTx, err := blocker.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = blockerTx.Rollback() })
	if _, err := blockerTx.Exec(`SELECT id FROM devradar_tenant WHERE id=$1 FOR UPDATE`, accountID); err != nil {
		t.Fatal(err)
	}
	var blockerPID int
	if err := blockerTx.QueryRow(`SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}

	responses := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() {
			req := accountFormRequest(http.MethodPost, "/account/invitations", session, csrfCookie,
				url.Values{"email": {email}, "role": {"reader"}, "csrf_token": {csrfToken}})
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			responses <- rec
		}()
	}
	blocked := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var count int
		if err := st.DB().QueryRow(`
			SELECT count(*) FROM pg_stat_activity
			WHERE pid<>$1 AND cardinality(pg_blocking_pids(pid))>0
			  AND query LIKE '%devradar_tenant%'`, blockerPID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 2 {
			blocked = true
			break
		}
		if len(responses) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := blockerTx.Commit(); err != nil {
		t.Fatal(err)
	}
	recorders := []*httptest.ResponseRecorder{<-responses, <-responses}
	if !blocked {
		t.Fatalf("both creates did not reach the account-lock barrier: statuses=%d/%d",
			recorders[0].Code, recorders[1].Code)
	}
	locations := map[string]int{}
	for _, rec := range recorders {
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("concurrent create = %d: %s", rec.Code, rec.Body.String())
		}
		locations[rec.Header().Get("Location")]++
	}
	if locations["/account/members?msg=invited"] != 1 || locations["/account/members?msg=pending"] != 1 {
		t.Fatalf("concurrent create locations = %#v", locations)
	}
	var invitations, outbox, audits int
	if err := st.DB().QueryRow(`
		SELECT (SELECT count(*) FROM devradar_account_invitation WHERE account_id=$1 AND normalized_email=$2),
		       (SELECT count(*) FROM devradar_delivery_outbox WHERE account_id=$1 AND recipient=$2),
		       (SELECT count(*) FROM devradar_audit_event
		        WHERE account_id=$1 AND action='invitation.create' AND metadata->>'recipient'=$2)`,
		accountID, email).Scan(&invitations, &outbox, &audits); err != nil {
		t.Fatal(err)
	}
	accountQuota := invitationRateCount(t, st, "invitation-account:"+accountID)
	recipientQuota := invitationRateCount(t, st, "invitation-recipient:"+email)
	if invitations != 1 || outbox != 1 || audits != 1 || accountQuota != 1 || recipientQuota != 1 {
		t.Fatalf("invitations/outbox/audits/account quota/recipient quota = %d/%d/%d/%d/%d",
			invitations, outbox, audits, accountQuota, recipientQuota)
	}
	pending := httptest.NewRequest(http.MethodGet, "/account/members?msg=pending", nil)
	pending.AddCookie(session)
	pendingRec := httptest.NewRecorder()
	h.ServeHTTP(pendingRec, pending)
	if pendingRec.Code != http.StatusOK || !strings.Contains(pendingRec.Body.String(), "Invitation is already pending.") {
		t.Fatalf("pending message = %d: %s", pendingRec.Code, pendingRec.Body.String())
	}
}

func TestInvitationRecipientQuotaDenialRollsBackAccountQuota(t *testing.T) {
	enableInvitationUI(t)
	t.Setenv("DEVRADAR_INVITATION_RATE_ACCOUNT", "1")
	t.Setenv("DEVRADAR_INVITATION_RATE_RECIPIENT", "1")
	srv, st := testServer(t)
	session, _, accountID := seedAccountSwitchSession(t, st)
	h := srv.Handler()
	csrfCookie, csrfToken := csrfFor(t, h, session, "/account/members")
	email := "recipient-limit-" + randomHex(t, 6) + "@example.com"
	recipientKey := "invitation-recipient:" + email
	if allowed, err := ratelimit.Allow(context.Background(), st.DB(), recipientKey, 1, time.Hour); err != nil || !allowed {
		t.Fatalf("seed recipient quota = %t, %v", allowed, err)
	}

	req := accountFormRequest(http.MethodPost, "/account/invitations", session, csrfCookie,
		url.Values{"email": {email}, "role": {"reader"}, "csrf_token": {csrfToken}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("recipient-limited create = %d: %s", rec.Code, rec.Body.String())
	}
	accountQuota := invitationRateCount(t, st, "invitation-account:"+accountID)
	recipientQuota := invitationRateCount(t, st, recipientKey)
	if accountQuota != 0 || recipientQuota != 1 {
		t.Fatalf("account/recipient quota after denial = %d/%d, want 0/1", accountQuota, recipientQuota)
	}
	var invitations, outbox, audits int
	if err := st.DB().QueryRow(`
		SELECT (SELECT count(*) FROM devradar_account_invitation WHERE account_id=$1 AND normalized_email=$2),
		       (SELECT count(*) FROM devradar_delivery_outbox WHERE account_id=$1 AND recipient=$2),
		       (SELECT count(*) FROM devradar_audit_event
		        WHERE account_id=$1 AND metadata->>'recipient'=$2)`, accountID, email).
		Scan(&invitations, &outbox, &audits); err != nil {
		t.Fatal(err)
	}
	if invitations != 0 || outbox != 0 || audits != 0 {
		t.Fatalf("denied invitation/outbox/audit = %d/%d/%d", invitations, outbox, audits)
	}
}

func TestInvitationAcceptanceGETIsScannerSafeAndPOSTCreatesSelectedSession(t *testing.T) {
	enableInvitationUI(t)
	srv, st := testServer(t)
	adminSession, adminID, accountID := seedAccountSwitchSession(t, st)
	_ = adminSession
	invite, err := st.CreateOrRefreshInvitation(context.Background(), accountID,
		"accept-http-"+randomHex(t, 6)+"@example.com", account.RoleReader,
		account.Actor{Kind: account.ActorUser, UserID: adminID}, randomHex(t, 16), invitationKey)
	if err != nil {
		t.Fatal(err)
	}
	raw := rawInvitationToken(t, st, invite)
	h := srv.Handler()
	path := "/account-invitations/" + invite.ID
	get := httptest.NewRequest(http.MethodGet, path, nil)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, get)
	if getRec.Code != http.StatusOK {
		t.Fatalf("accept GET = %d: %s", getRec.Code, getRec.Body.String())
	}
	assertInvitationResponseHeaders(t, getRec)
	if strings.Contains(getRec.Body.String(), raw) {
		t.Fatal("acceptance GET exposed raw token in response")
	}
	for _, want := range []string{"Access invitation", invite.AccountName, "Reader", invite.InvitedByEmail, "Accept invitation"} {
		if !strings.Contains(getRec.Body.String(), want) {
			t.Fatalf("acceptance page missing %q: %s", want, getRec.Body.String())
		}
	}
	for _, want := range []string{`action="` + path + `"`, `data-invitation-accept`, `name="token" value=""`, `disabled`} {
		if !strings.Contains(getRec.Body.String(), want) {
			t.Fatalf("acceptance page missing fragment handoff marker %q: %s", want, getRec.Body.String())
		}
	}
	var oldPathLogs strings.Builder
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&oldPathLogs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })
	oldPath := httptest.NewRequest(http.MethodGet, "/invitations/"+raw, nil)
	oldPathRec := httptest.NewRecorder()
	h.ServeHTTP(oldPathRec, oldPath)
	slog.SetDefault(previousLogger)
	if oldPathRec.Code != http.StatusNotFound || oldPathRec.Header().Get("Location") != "" {
		t.Fatalf("old raw-token path = %d location %q, want unredirected 404",
			oldPathRec.Code, oldPathRec.Header().Get("Location"))
	}
	if strings.Contains(oldPathLogs.String(), raw) {
		t.Fatalf("old raw-token path was logged: %s", oldPathLogs.String())
	}
	missing := httptest.NewRequest(http.MethodGet,
		"/account-invitations/00000000-0000-0000-0000-000000000000", nil)
	missingRec := httptest.NewRecorder()
	h.ServeHTTP(missingRec, missing)
	if missingRec.Code != http.StatusNotFound {
		t.Fatalf("missing invitation = %d, want 404", missingRec.Code)
	}
	assertInvitationResponseHeaders(t, missingRec)
	jsReq := httptest.NewRequest(http.MethodGet, "/static/js/app.js", nil)
	jsRec := httptest.NewRecorder()
	h.ServeHTTP(jsRec, jsReq)
	for _, want := range []string{"window.location.hash", "history.replaceState", "data-invitation-accept"} {
		if jsRec.Code != http.StatusOK || !strings.Contains(jsRec.Body.String(), want) {
			t.Fatalf("invitation fragment JS missing %q: status=%d", want, jsRec.Code)
		}
	}
	var accepted int
	if err := st.DB().QueryRow(`SELECT count(*) FROM devradar_account_invitation WHERE id=$1 AND accepted_at IS NOT NULL`, invite.ID).Scan(&accepted); err != nil || accepted != 0 {
		t.Fatalf("GET consumed invitation = %d, %v", accepted, err)
	}
	csrfToken := scrapeCSRF(t, getRec.Body.String())
	var csrfCookie *http.Cookie
	for _, cookie := range getRec.Result().Cookies() {
		if cookie.Name == middleware.CSRFCookieName() {
			csrfCookie = cookie
		}
	}
	without := httptest.NewRequest(http.MethodPost, path, strings.NewReader(url.Values{"csrf_token": {csrfToken}, "token": {raw}}.Encode()))
	without.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	withoutRec := httptest.NewRecorder()
	h.ServeHTTP(withoutRec, without)
	if withoutRec.Code != http.StatusForbidden {
		t.Fatalf("accept without CSRF cookie = %d", withoutRec.Code)
	}
	assertInvitationResponseHeaders(t, withoutRec)

	post := httptest.NewRequest(http.MethodPost, path, strings.NewReader(url.Values{"csrf_token": {csrfToken}, "token": {raw}}.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(csrfCookie)
	postRec := httptest.NewRecorder()
	h.ServeHTTP(postRec, post)
	if postRec.Code != http.StatusFound || postRec.Header().Get("Location") != "/overview" {
		t.Fatalf("accept POST = %d location %q: %s", postRec.Code, postRec.Header().Get("Location"), postRec.Body.String())
	}
	assertInvitationResponseHeaders(t, postRec)
	var sessionCookie *http.Cookie
	for _, cookie := range postRec.Result().Cookies() {
		if cookie.Name == middleware.SessionCookieName() && cookie.Value != "" {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil {
		t.Fatal("acceptance did not create a session")
	}
	session, err := st.ValidateSession(context.Background(), sessionCookie.Value)
	if err != nil || session.ActiveAccountID == nil || *session.ActiveAccountID != accountID {
		t.Fatalf("accepted session = %#v, %v", session, err)
	}

	replay := httptest.NewRequest(http.MethodPost, path, strings.NewReader(url.Values{"csrf_token": {csrfToken}, "token": {raw}}.Encode()))
	replay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replay.AddCookie(csrfCookie)
	replayRec := httptest.NewRecorder()
	h.ServeHTTP(replayRec, replay)
	if replayRec.Code != http.StatusConflict || !strings.Contains(replayRec.Body.String(), "already accepted") {
		t.Fatalf("anonymous replay = %d: %s", replayRec.Code, replayRec.Body.String())
	}
	assertInvitationResponseHeaders(t, replayRec)
	assertInvitationDurableCounts(t, st, accountID, session.User.ID, 1)

	authedReplay := accountFormRequest(http.MethodPost, path, sessionCookie, csrfCookie,
		url.Values{"csrf_token": {csrfToken}, "token": {raw}})
	authedReplayRec := httptest.NewRecorder()
	h.ServeHTTP(authedReplayRec, authedReplay)
	if authedReplayRec.Code != http.StatusFound || authedReplayRec.Header().Get("Location") != "/overview" {
		t.Fatalf("authenticated replay = %d location %q: %s", authedReplayRec.Code, authedReplayRec.Header().Get("Location"), authedReplayRec.Body.String())
	}
	assertInvitationDurableCounts(t, st, accountID, session.User.ID, 1)
}

func TestInvitationConcurrentHTTPAcceptanceCreatesOneSession(t *testing.T) {
	enableInvitationUI(t)
	srv, st := testServer(t)
	_, adminID, accountID := seedAccountSwitchSession(t, st)
	email := "http-race-" + randomHex(t, 6) + "@example.com"
	invite, err := st.CreateOrRefreshInvitation(context.Background(), accountID, email, account.RoleEditor,
		account.Actor{Kind: account.ActorUser, UserID: adminID}, randomHex(t, 16), invitationKey)
	if err != nil {
		t.Fatal(err)
	}
	raw := rawInvitationToken(t, st, invite)
	path := "/account-invitations/" + invite.ID
	h := srv.Handler()
	csrfCookie, csrfToken := csrfFor(t, h, anonymousTestCookie(), path)

	start := make(chan struct{})
	responses := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() {
			<-start
			req := httptest.NewRequest(http.MethodPost, path,
				strings.NewReader(url.Values{"csrf_token": {csrfToken}, "token": {raw}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(csrfCookie)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			responses <- rec
		}()
	}
	close(start)
	var redirected, rejected int
	for range 2 {
		rec := <-responses
		assertInvitationResponseHeaders(t, rec)
		switch rec.Code {
		case http.StatusFound:
			redirected++
		case http.StatusConflict:
			rejected++
		default:
			t.Fatalf("concurrent accept status = %d: %s", rec.Code, rec.Body.String())
		}
	}
	if redirected != 1 || rejected != 1 {
		t.Fatalf("concurrent redirects/rejections = %d/%d, want 1/1", redirected, rejected)
	}
	var userID string
	if err := st.DB().QueryRow(`SELECT id FROM devradar_user WHERE email=$1`, email).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	assertInvitationDurableCounts(t, st, accountID, userID, 1)
}

func TestInvitationAcceptedExpiredReplayCannotCreateSession(t *testing.T) {
	enableInvitationUI(t)
	srv, st := testServer(t)
	_, adminID, accountID := seedAccountSwitchSession(t, st)
	email := "http-expired-replay-" + randomHex(t, 6) + "@example.com"
	invite, err := st.CreateOrRefreshInvitation(context.Background(), accountID, email, account.RoleReader,
		account.Actor{Kind: account.ActorUser, UserID: adminID}, randomHex(t, 16), invitationKey)
	if err != nil {
		t.Fatal(err)
	}
	raw := rawInvitationToken(t, st, invite)
	path := "/account-invitations/" + invite.ID
	h := srv.Handler()
	csrfCookie, csrfToken := csrfFor(t, h, anonymousTestCookie(), path)
	accept := httptest.NewRequest(http.MethodPost, path,
		strings.NewReader(url.Values{"csrf_token": {csrfToken}, "token": {raw}}.Encode()))
	accept.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	accept.AddCookie(csrfCookie)
	acceptRec := httptest.NewRecorder()
	h.ServeHTTP(acceptRec, accept)
	if acceptRec.Code != http.StatusFound {
		t.Fatalf("first accept = %d: %s", acceptRec.Code, acceptRec.Body.String())
	}
	if _, err := st.DB().Exec(`
		UPDATE devradar_account_invitation
		SET created_at=created_at-interval '8 days',expires_at=now()-interval '1 day',updated_at=now()
		WHERE id=$1`, invite.ID); err != nil {
		t.Fatal(err)
	}
	replay := httptest.NewRequest(http.MethodPost, path,
		strings.NewReader(url.Values{"csrf_token": {csrfToken}, "token": {raw}}.Encode()))
	replay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replay.AddCookie(csrfCookie)
	replayRec := httptest.NewRecorder()
	h.ServeHTTP(replayRec, replay)
	if replayRec.Code != http.StatusConflict {
		t.Fatalf("expired accepted replay = %d: %s", replayRec.Code, replayRec.Body.String())
	}
	var userID string
	if err := st.DB().QueryRow(`SELECT id FROM devradar_user WHERE email=$1`, email).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	assertInvitationDurableCounts(t, st, accountID, userID, 1)
}

func TestInvitationAcceptanceRejectsDifferentSignedInEmail(t *testing.T) {
	enableInvitationUI(t)
	srv, st := testServer(t)
	session, adminID, accountID := seedAccountSwitchSession(t, st)
	invite, err := st.CreateOrRefreshInvitation(context.Background(), accountID,
		"other-"+randomHex(t, 6)+"@example.com", account.RoleReader,
		account.Actor{Kind: account.ActorUser, UserID: adminID}, randomHex(t, 16), invitationKey)
	if err != nil {
		t.Fatal(err)
	}
	raw := rawInvitationToken(t, st, invite)
	h := srv.Handler()
	path := "/account-invitations/" + invite.ID
	csrfCookie, csrfToken := csrfFor(t, h, session, path)
	req := accountFormRequest(http.MethodPost, path, session, csrfCookie,
		url.Values{"csrf_token": {csrfToken}, "token": {raw}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "signed in with a different email") {
		t.Fatalf("different email = %d: %s", rec.Code, rec.Body.String())
	}
	var accepted int
	if err := st.DB().QueryRow(`SELECT count(*) FROM devradar_account_invitation WHERE id=$1 AND accepted_at IS NOT NULL`, invite.ID).Scan(&accepted); err != nil || accepted != 0 {
		t.Fatalf("different-email acceptance mutated = %d, %v", accepted, err)
	}
}

func TestAccountMembersShowsSafeInvitationDeliveryFailure(t *testing.T) {
	enableInvitationUI(t)
	srv, st := testServer(t)
	session, adminID, accountID := seedAccountSwitchSession(t, st)
	invite, err := st.CreateOrRefreshInvitation(context.Background(), accountID,
		"failed-ui-"+randomHex(t, 6)+"@example.com", account.RoleReader,
		account.Actor{Kind: account.ActorUser, UserID: adminID}, randomHex(t, 16), invitationKey)
	if err != nil {
		t.Fatal(err)
	}
	raw := rawInvitationToken(t, st, invite)
	var encrypted string
	if err := st.DB().QueryRow(`
		SELECT encrypted_payload FROM devradar_delivery_outbox
		WHERE account_id=$1 AND invitation_id=$2 AND invitation_version=$3`,
		accountID, invite.ID, invite.TokenVersion).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	providerError := "provider bearer private-error-" + randomHex(t, 6)
	if _, err := st.DB().Exec(`
		UPDATE devradar_delivery_outbox
		SET status='permanently_failed',encrypted_payload='',last_error=$4,
		    permanently_failed_at=clock_timestamp(),updated_at=clock_timestamp()
		WHERE account_id=$1 AND invitation_id=$2 AND invitation_version=$3`,
		accountID, invite.ID, invite.TokenVersion, providerError); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/account/members", nil)
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "Delivery failed") ||
		!strings.Contains(body, "Send again to retry.") {
		t.Fatalf("failed invitation state = %d: %s", rec.Code, body)
	}
	for _, secret := range []string{providerError, raw, encrypted} {
		if strings.Contains(body, secret) {
			t.Fatalf("failed invitation page exposed delivery secret %q: %s", secret, body)
		}
	}
}

func TestInvitationManagementRequiresAdminAndRateLimitDoesNotMutate(t *testing.T) {
	enableInvitationUI(t)
	t.Setenv("DEVRADAR_INVITATION_RATE_ACCOUNT", "1")
	srv, st := testServer(t)
	adminSession, adminID, accountID := seedAccountSwitchSession(t, st)
	editorID := seedAdditionalMember(t, st, accountID, account.RoleEditor, adminID)
	editorRaw, err := st.CreateSession(context.Background(), editorID, &accountID, sessionTTLForTest)
	if err != nil {
		t.Fatal(err)
	}
	editorSession := &http.Cookie{Name: middleware.SessionCookieName(), Value: editorRaw}
	h := srv.Handler()
	editorCSRF, editorToken := csrfFor(t, h, editorSession, "/accounts")
	editorReq := accountFormRequest(http.MethodPost, "/account/invitations", editorSession, editorCSRF,
		url.Values{"email": {"denied-" + randomHex(t, 5) + "@example.com"}, "role": {"reader"}, "csrf_token": {editorToken}})
	editorRec := httptest.NewRecorder()
	h.ServeHTTP(editorRec, editorReq)
	if editorRec.Code != http.StatusForbidden {
		t.Fatalf("editor invitation = %d, want 403", editorRec.Code)
	}

	csrfCookie, csrfToken := csrfFor(t, h, adminSession, "/account/members")
	firstEmail := "limit-first-" + randomHex(t, 5) + "@example.com"
	first := accountFormRequest(http.MethodPost, "/account/invitations", adminSession, csrfCookie,
		url.Values{"email": {firstEmail}, "role": {"reader"}, "csrf_token": {csrfToken}})
	firstRec := httptest.NewRecorder()
	h.ServeHTTP(firstRec, first)
	if firstRec.Code != http.StatusSeeOther {
		t.Fatalf("first limited invitation = %d: %s", firstRec.Code, firstRec.Body.String())
	}
	duplicate := accountFormRequest(http.MethodPost, "/account/invitations", adminSession, csrfCookie,
		url.Values{"email": {strings.ToUpper(firstEmail)}, "role": {"reader"}, "csrf_token": {csrfToken}})
	duplicateRec := httptest.NewRecorder()
	h.ServeHTTP(duplicateRec, duplicate)
	if duplicateRec.Code != http.StatusSeeOther || duplicateRec.Header().Get("Location") != "/account/members?msg=pending" {
		t.Fatalf("duplicate limited invitation = %d location %q: %s",
			duplicateRec.Code, duplicateRec.Header().Get("Location"), duplicateRec.Body.String())
	}
	secondEmail := "limit-second-" + randomHex(t, 5) + "@example.com"
	second := accountFormRequest(http.MethodPost, "/account/invitations", adminSession, csrfCookie,
		url.Values{"email": {secondEmail}, "role": {"reader"}, "csrf_token": {csrfToken}})
	secondRec := httptest.NewRecorder()
	h.ServeHTTP(secondRec, second)
	if secondRec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-limit invitation = %d, want 429: %s", secondRec.Code, secondRec.Body.String())
	}
	var rows int
	if err := st.DB().QueryRow(`SELECT count(*) FROM devradar_account_invitation WHERE account_id=$1 AND normalized_email=$2`, accountID, secondEmail).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("over-limit invitation rows = %d, %v", rows, err)
	}
}

func TestInvitationSessionFailureKeepsAcceptedMembership(t *testing.T) {
	enableInvitationUI(t)
	srv, st := testServer(t)
	_, adminID, accountID := seedAccountSwitchSession(t, st)
	email := "session-failure-" + randomHex(t, 6) + "@example.com"
	var userID string
	if err := st.DB().QueryRow(`INSERT INTO devradar_user(email,email_verified_at) VALUES($1,now()) RETURNING id`, email).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	chooserRaw, err := st.CreateSession(context.Background(), userID, nil, sessionTTLForTest)
	if err != nil {
		t.Fatal(err)
	}
	chooser := &http.Cookie{Name: middleware.SessionCookieName(), Value: chooserRaw}
	invite, err := st.CreateOrRefreshInvitation(context.Background(), accountID, email, account.RoleReader,
		account.Actor{Kind: account.ActorUser, UserID: adminID}, randomHex(t, 16), invitationKey)
	if err != nil {
		t.Fatal(err)
	}
	raw := rawInvitationToken(t, st, invite)
	trigger := "reject_session_" + randomHex(t, 5)
	function := trigger + "_fn"
	if _, err := st.DB().Exec(`CREATE FUNCTION ` + function + `() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'forced session failure'; END $$`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`CREATE TRIGGER ` + trigger + ` BEFORE INSERT ON devradar_session FOR EACH ROW WHEN (NEW.user_id='` + userID + `'::uuid) EXECUTE FUNCTION ` + function + `()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = st.DB().Exec(`DROP TRIGGER IF EXISTS ` + trigger + ` ON devradar_session`)
		_, _ = st.DB().Exec(`DROP FUNCTION IF EXISTS ` + function + `()`)
	})
	h := srv.Handler()
	path := "/account-invitations/" + invite.ID
	csrfCookie, csrfToken := csrfFor(t, h, chooser, path)
	req := accountFormRequest(http.MethodPost, path, chooser, csrfCookie,
		url.Values{"csrf_token": {csrfToken}, "token": {raw}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "Access was accepted") {
		t.Fatalf("session failure = %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := st.GetAccess(context.Background(), userID, accountID); err != nil {
		t.Fatalf("membership rolled back with session failure: %v", err)
	}
}

func rawInvitationToken(t *testing.T, st *postgres.Store, invitation *postgres.Invitation) string {
	t.Helper()
	var encrypted, key string
	if err := st.DB().QueryRow(`SELECT encrypted_payload,idempotency_key FROM devradar_delivery_outbox WHERE invitation_id=$1 AND invitation_version=$2`, invitation.ID, invitation.TokenVersion).Scan(&encrypted, &key); err != nil {
		t.Fatal(err)
	}
	raw, err := secretbox.Open(invitationKey, encrypted, []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func assertInvitationResponseHeaders(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy = %q, want no-referrer", got)
	}
}

func assertInvitationDurableCounts(t *testing.T, st *postgres.Store, accountID, userID string, sessions int) {
	t.Helper()
	var gotSessions, memberships, audits int
	if err := st.DB().QueryRow(`
		SELECT (SELECT count(*) FROM devradar_session WHERE user_id=$1),
		       (SELECT count(*) FROM devradar_account_member WHERE account_id=$2 AND user_id=$1),
		       (SELECT count(*) FROM devradar_audit_event WHERE account_id=$2 AND action='invitation.accept')`,
		userID, accountID).Scan(&gotSessions, &memberships, &audits); err != nil {
		t.Fatal(err)
	}
	if gotSessions != sessions || memberships != 1 || audits != 1 {
		t.Fatalf("sessions/memberships/audits = %d/%d/%d, want %d/1/1",
			gotSessions, memberships, audits, sessions)
	}
}

func invitationRateCount(t *testing.T, st *postgres.Store, key string) int {
	t.Helper()
	var count int
	if err := st.DB().QueryRow(`
		SELECT COALESCE(sum(count),0) FROM devradar_rate_event WHERE bucket_key=$1`, key).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

const sessionTTLForTest = time.Hour

func anonymousTestCookie() *http.Cookie {
	return &http.Cookie{Name: "test-only", Value: "anonymous"}
}

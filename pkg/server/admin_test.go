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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/gcs"
	"github.com/thingzio/devradar/pkg/middleware"
	"github.com/thingzio/devradar/pkg/server"
)

// platformActorEmail reads the verified user email for a compatibility account so a
// test can add the person, rather than the account, to the operator allowlist.
func platformActorEmail(t *testing.T, st *postgres.Store, id string) string {
	t.Helper()
	userID := seedLegacyUser(t, st, id)
	user, err := st.GetUser(context.Background(), userID)
	if err != nil {
		t.Fatalf("get actor: %v", err)
	}
	return user.Email
}

func seedAdminProductHealth(t *testing.T, st *postgres.Store, tenantID string) {
	t.Helper()
	ctx := context.Background()
	repository := "registry.test/admin-health-" + tenantID
	sboms := []*postgres.SBOM{
		{
			ID: "admin-health-1-" + tenantID, TenantID: tenantID,
			ImageRef: repository + ":v1", Repository: repository, Version: "v1",
			Digest: "sha256:admin-health-1-" + tenantID, Format: "cyclonedx",
			ObjectPath: "gs://test/admin-health-1-" + tenantID, Status: "active",
		},
		{
			ID: "admin-health-2-" + tenantID, TenantID: tenantID,
			ImageRef: repository + ":v2", Repository: repository, Version: "v2",
			Digest: "sha256:admin-health-2-" + tenantID, Format: "cyclonedx",
			ObjectPath: "gs://test/admin-health-2-" + tenantID, Status: "active",
		},
	}
	for _, sb := range sboms {
		if _, _, _, err := st.UpsertSBOM(ctx, sb); err != nil {
			t.Fatalf("seed product-health SBOM: %v", err)
		}
	}

	var policyID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_alert_policy (tenant_id, enabled)
		VALUES ($1, true) RETURNING id`, tenantID).Scan(&policyID); err != nil {
		t.Fatalf("seed alert policy: %v", err)
	}
	eventID := time.Now().UnixNano()
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_alert
		(tenant_id, policy_id, event_id, event_occurred_at, alert_kind, sbom_id,
		 repository, digest, finding_id, exposure, package, version, severity, score, cause)
		VALUES ($1,$2,$3,now(),'new_finding',$4,$5,$6,'finding-admin-health',
		        'CVE-2099-9999','pkg','1','high',8,'image')`,
		tenantID, policyID, eventID, sboms[0].ID, repository, sboms[0].Digest); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_alert_failure
		(consumer, event_id, event_occurred_at, error)
		VALUES ($1,$2,now(),'test evaluator failure')`, "admin-test-"+tenantID, eventID); err != nil {
		t.Fatalf("seed evaluator failure: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_tenant_posture_snapshot (tenant_id, snapshot_date, images)
		VALUES ($1, (now() AT TIME ZONE 'UTC')::date, 2)`, tenantID); err != nil {
		t.Fatalf("seed posture snapshot: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_finding
		(sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
		VALUES ($1,'grype','finding-admin-health','CVE-2099-9999','pkg','1','high',8,true)`,
		sboms[0].ID); err != nil {
		t.Fatalf("seed canonical exposure: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_cve_enrichment (cve, kev)
		VALUES ('CVE-2099-9999', true)
		ON CONFLICT (cve) DO UPDATE SET kev=true`); err != nil {
		t.Fatalf("seed KEV enrichment: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_license_policy (tenant_id, denied_categories)
		VALUES ($1, ARRAY['strong-copyleft'])`, tenantID); err != nil {
		t.Fatalf("seed license policy: %v", err)
	}
}

// TestAdmin_NonAdmin404 verifies the console is hidden: an authenticated but
// non-allowlisted tenant gets 404 (not 403), and an unauthenticated request too.
func TestAdmin_NonAdmin404(t *testing.T) {
	t.Setenv("DEVRADAR_ADMIN_USERS", "someone-else@example.com")
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	h := srv.Handler()
	cookie := seedSession(t, st, tenantID)

	// Authenticated non-admin → 404.
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("non-admin /admin: status = %d, want 404", rec.Code)
	}

	// Unauthenticated → 404 (no redirect that would disclose the route).
	req2 := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Errorf("unauth /admin: status = %d, want 404", rec2.Code)
	}
}

// TestAdmin_AdminSeesProductHealth verifies an allowlisted tenant sees the
// aggregate product-health section without tenant identities or unsafe claims.
func TestAdmin_AdminSeesProductHealth(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	adminEmail := platformActorEmail(t, st, tenantID)
	t.Setenv("DEVRADAR_ADMIN_USERS", adminEmail)
	observedTenantID, _ := seedTenantToken(t, st)
	observedEmail := platformActorEmail(t, st, observedTenantID)
	seedAdminProductHealth(t, st, observedTenantID)
	h := srv.Handler()
	cookie := seedSession(t, st, tenantID)

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin /admin: status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Platform") {
		t.Error("dashboard body should contain the Platform heading")
	}
	for _, want := range []string{
		"Product health", "Alert adoption", "Evaluator", "Posture coverage",
		"Actionable exposure", "Comparison readiness", "License policy adoption",
		"current UTC date", time.Now().UTC().Format("2006-01-02"),
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	start := strings.Index(body, `<section aria-labelledby="product-health-heading">`)
	if start < 0 {
		t.Fatal("missing product-health section")
	}
	end := strings.Index(body[start:], `</section>`)
	if end < 0 {
		t.Fatal("unterminated product-health section")
	}
	productHealth := body[start : start+end]
	for _, identity := range []string{adminEmail, observedEmail} {
		if strings.Contains(productHealth, identity) {
			t.Errorf("product-health section contains tenant identity %q", identity)
		}
	}
	lowerBody := strings.ToLower(body)
	for _, forbidden := range []string{"safe", "compatible", "reachable", "compliant"} {
		if strings.Contains(lowerBody, forbidden) {
			t.Errorf("dashboard contains forbidden claim %q", forbidden)
		}
	}
}

// TestAdmin_CSRFRequired verifies a mutating POST without a valid CSRF token is
// rejected 403, and the same POST with matching cookie+field succeeds (303).
func TestAdmin_CSRFRequired(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	t.Setenv("DEVRADAR_ADMIN_USERS", platformActorEmail(t, st, tenantID))
	h := srv.Handler()
	cookie := seedSession(t, st, tenantID)

	target, _ := seedTenantToken(t, st) // the tenant we mutate

	// No CSRF token → 403.
	body := "plan=paid"
	req := httptest.NewRequest(http.MethodPost, "/admin/account/"+target+"/plan", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without CSRF: status = %d, want 403", rec.Code)
	}

	// With a matching double-submit token → 303.
	tok, err := middleware.GenerateCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	req2 := httptest.NewRequest(http.MethodPost, "/admin/account/"+target+"/plan",
		strings.NewReader("plan=paid&csrf_token="+tok))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.AddCookie(cookie)
	req2.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName(), Value: tok})
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusSeeOther {
		t.Fatalf("POST with CSRF: status = %d, want 303", rec2.Code)
	}
	acct, _ := st.GetAccount(context.Background(), target)
	if acct.Plan != "paid" {
		t.Errorf("plan = %q, want paid (mutation should have applied)", acct.Plan)
	}
}

func TestAdminSharedMutationUsesPlatformActor(t *testing.T) {
	srv, st := testServer(t)
	adminAccountID, _ := seedTenantToken(t, st)
	t.Setenv("DEVRADAR_ADMIN_USERS", platformActorEmail(t, st, adminAccountID))
	h := srv.Handler()
	cookie := seedSession(t, st, adminAccountID)
	targetAccountID, _ := seedTenantToken(t, st)
	token, err := middleware.GenerateCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost,
		"/admin/account/"+targetAccountID+"/min-severity",
		strings.NewReader("min_severity=high&csrf_token="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName(), Value: token})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("platform setting mutation status = %d, want 303", rec.Code)
	}
	var kind, userID, requestID string
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT actor_kind,actor_user_id::text,request_id
		FROM devradar_audit_event
		WHERE account_id=$1 AND action='account.min_severity.update'`, targetAccountID).
		Scan(&kind, &userID, &requestID); err != nil {
		t.Fatalf("read platform audit: %v", err)
	}
	if kind != "platform" || userID == "" || requestID != rec.Header().Get("X-Request-ID") {
		t.Fatalf("platform attribution = %s/%s/%s, response %s", kind, userID, requestID,
			rec.Header().Get("X-Request-ID"))
	}
}

func TestAdminAccountCanonicalAndLegacyRoutes(t *testing.T) {
	srv, st := testServer(t)
	adminAccountID, _ := seedTenantToken(t, st)
	adminEmail := platformActorEmail(t, st, adminAccountID)
	t.Setenv("DEVRADAR_ADMIN_USERS", adminEmail)
	session := seedSession(t, st, adminAccountID)
	targetAccountID, _ := seedTenantToken(t, st)
	seedLegacyUser(t, st, targetAccountID)
	targetEmail := platformActorEmail(t, st, targetAccountID)
	if _, err := st.DB().ExecContext(context.Background(), `
		UPDATE devradar_tenant SET name='Canonical account' WHERE id=$1`, targetAccountID); err != nil {
		t.Fatalf("name target account: %v", err)
	}
	h := srv.Handler()

	list := httptest.NewRequest(http.MethodGet, "/admin/accounts?q="+url.QueryEscape(targetEmail), nil)
	list.AddCookie(session)
	listRec := httptest.NewRecorder()
	h.ServeHTTP(listRec, list)
	if listRec.Code != http.StatusOK {
		t.Fatalf("canonical account list = %d: %s", listRec.Code, listRec.Body.String())
	}
	for _, want := range []string{
		"Accounts", "Canonical account", targetEmail, ">1<", "/admin/account/" + targetAccountID,
		`for="admin-account-search"`, `id="admin-account-search"`,
		`for="admin-signup-email"`, `id="admin-signup-email"`,
	} {
		if !strings.Contains(listRec.Body.String(), want) {
			t.Fatalf("canonical account list missing %q: %s", want, listRec.Body.String())
		}
	}

	detail := httptest.NewRequest(http.MethodGet, "/admin/account/"+targetAccountID, nil)
	detail.AddCookie(session)
	detailRec := httptest.NewRecorder()
	h.ServeHTTP(detailRec, detail)
	if detailRec.Code != http.StatusOK || !strings.Contains(detailRec.Body.String(), "Canonical account") ||
		!strings.Contains(detailRec.Body.String(), targetEmail) {
		t.Fatalf("canonical account detail = %d: %s", detailRec.Code, detailRec.Body.String())
	}
	for _, association := range []string{
		`<label for="admin-account-plan"`, `id="admin-account-plan"`,
		`<label for="admin-account-status"`, `id="admin-account-status"`,
		`<label for="admin-account-min-severity"`, `id="admin-account-min-severity"`,
	} {
		if !strings.Contains(detailRec.Body.String(), association) {
			t.Fatalf("canonical account detail missing label association %q: %s", association, detailRec.Body.String())
		}
	}

	for legacy, canonical := range map[string]string{
		"/admin/tenants":                   "/admin/accounts",
		"/admin/tenant/" + targetAccountID: "/admin/account/" + targetAccountID,
	} {
		req := httptest.NewRequest(http.MethodGet, legacy, nil)
		req.AddCookie(session)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != canonical {
			t.Fatalf("legacy %s = %d %q, want 301 %q", legacy, rec.Code, rec.Header().Get("Location"), canonical)
		}
	}
}

func TestAdminAccountAPITokensRemainAccountScoped(t *testing.T) {
	srv, st := testServer(t)
	adminAccountID, _ := seedTenantToken(t, st)
	t.Setenv("DEVRADAR_ADMIN_USERS", platformActorEmail(t, st, adminAccountID))
	session := seedSession(t, st, adminAccountID)
	targetAccountID, _ := seedTenantToken(t, st)
	foreignAccountID, _ := seedTenantToken(t, st)
	var targetTokenID, foreignTokenID string
	if err := st.DB().QueryRowContext(context.Background(), `
		INSERT INTO devradar_api_token (tenant_id,name,token_hash)
		VALUES ($1,'canonical target credential',$2) RETURNING id`, targetAccountID, randomHex(t, 16)).Scan(&targetTokenID); err != nil {
		t.Fatalf("seed target token: %v", err)
	}
	if err := st.DB().QueryRowContext(context.Background(), `
		INSERT INTO devradar_api_token (tenant_id,name,token_hash)
		VALUES ($1,'foreign credential',$2) RETURNING id`, foreignAccountID, randomHex(t, 16)).Scan(&foreignTokenID); err != nil {
		t.Fatalf("seed foreign token: %v", err)
	}
	h := srv.Handler()
	detail := httptest.NewRequest(http.MethodGet, "/admin/account/"+targetAccountID, nil)
	detail.AddCookie(session)
	detailRec := httptest.NewRecorder()
	h.ServeHTTP(detailRec, detail)
	if detailRec.Code != http.StatusOK || !strings.Contains(detailRec.Body.String(), "canonical target credential") ||
		strings.Contains(detailRec.Body.String(), "foreign credential") {
		t.Fatalf("account-scoped tokens detail = %d: %s", detailRec.Code, detailRec.Body.String())
	}
	csrfCookie, csrfToken := csrfFor(t, h, session, "/admin/account/"+targetAccountID)
	revoke := httptest.NewRequest(http.MethodPost,
		"/admin/account/"+targetAccountID+"/token/"+targetTokenID+"/revoke",
		strings.NewReader("csrf_token="+csrfToken))
	revoke.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revoke.AddCookie(session)
	revoke.AddCookie(csrfCookie)
	revokeRec := httptest.NewRecorder()
	h.ServeHTTP(revokeRec, revoke)
	if revokeRec.Code != http.StatusSeeOther {
		t.Fatalf("canonical token revoke = %d: %s", revokeRec.Code, revokeRec.Body.String())
	}
	assertAPITokenExists(t, st, targetAccountID, targetTokenID, false)
	assertAPITokenExists(t, st, foreignAccountID, foreignTokenID, true)
}

func TestAdminInviteSendsOrdinarySignupWithoutPrecreatingIdentity(t *testing.T) {
	_, st := testServer(t)
	sender := &recordingSender{}
	srv := server.New(st, gcs.LocalStore{Dir: t.TempDir()}, sender, nil, nil, server.Options{Version: "test"})
	adminAccountID, _ := seedTenantToken(t, st)
	t.Setenv("DEVRADAR_ADMIN_USERS", platformActorEmail(t, st, adminAccountID))
	session := seedSession(t, st, adminAccountID)
	h := srv.Handler()
	csrfCookie, csrfToken := csrfFor(t, h, session, "/admin/accounts")
	targetEmail := "admin-signup-" + randomHex(t, 6) + "@example.com"
	req := httptest.NewRequest(http.MethodPost, "/admin/invite", strings.NewReader(url.Values{
		"email": {targetEmail}, "csrf_token": {csrfToken},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	req.AddCookie(csrfCookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/accounts?msg=signup_sent" {
		t.Fatalf("admin signup delivery = %d %q: %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	sender.mu.Lock()
	message := sender.message
	sender.mu.Unlock()
	if message.To != targetEmail || message.Subject != "Your DevRadar sign-in link" ||
		!strings.Contains(message.Text, "/auth/verify?token=") || !strings.HasPrefix(message.IdempotencyKey, "magic-link/") {
		t.Fatalf("admin signup did not use ordinary magic-link delivery: %#v", message)
	}
	assertIdentityCounts(t, st, targetEmail, 0, 0, 1)

	raw := strings.SplitN(strings.SplitN(message.Text, "token=", 2)[1], "\n", 2)[0]
	identity, err := st.ConsumeLoginToken(context.Background(), raw)
	if err != nil {
		t.Fatalf("consume delivered signup token: %v", err)
	}
	if _, account, err := st.ResolveDirectIdentity(context.Background(), identity); err != nil || account == nil {
		t.Fatalf("resolve delivered signup = %#v, %v", account, err)
	}
	assertIdentityCounts(t, st, targetEmail, 1, 1, 0)
}

func assertAPITokenExists(t *testing.T, st *postgres.Store, accountID, tokenID string, want bool) {
	t.Helper()
	var got bool
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT EXISTS(SELECT 1 FROM devradar_api_token WHERE tenant_id=$1 AND id=$2)`,
		accountID, tokenID).Scan(&got); err != nil {
		t.Fatalf("read API token: %v", err)
	}
	if got != want {
		t.Fatalf("API token %s in account %s exists=%v, want %v", tokenID, accountID, got, want)
	}
}

func assertIdentityCounts(t *testing.T, st *postgres.Store, email string, users, accounts, tokens int) {
	t.Helper()
	var gotUsers, gotAccounts, gotTokens int
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT
			(SELECT count(*) FROM devradar_user WHERE email=$1),
			(SELECT count(*) FROM devradar_tenant WHERE email=$1),
			(SELECT count(*) FROM devradar_login_token WHERE email=$1)`, email).
		Scan(&gotUsers, &gotAccounts, &gotTokens); err != nil {
		t.Fatalf("read signup state: %v", err)
	}
	if gotUsers != users || gotAccounts != accounts || gotTokens != tokens {
		t.Fatalf("signup state users/accounts/tokens = %d/%d/%d, want %d/%d/%d",
			gotUsers, gotAccounts, gotTokens, users, accounts, tokens)
	}
}

// TestAdmin_ForceRescanCycle verifies the operator "force rescan" makes an SBOM
// due for scanning even when it was just scanned, and that ClearRescanRequested
// (invoked by the scan loop after every scanner has run) consumes the marker so
// the override fires exactly once.
func TestAdmin_ForceRescanCycle(t *testing.T) {
	_, st := testServer(t)
	ctx := context.Background()
	tenantID, _ := seedTenantToken(t, st)

	// One active SBOM.
	sb := &postgres.SBOM{
		ID: "sbom-rescan-" + tenantID, TenantID: tenantID, ImageRef: "img@sha256:abc",
		Repository: "img", Digest: "sha256:abc", Format: "cyclonedx", ObjectPath: "gs://x/y", Status: "active",
	}
	if _, _, _, err := st.UpsertSBOM(ctx, sb); err != nil {
		t.Fatalf("upsert sbom: %v", err)
	}

	grypeOnly := []string{"grype"}

	// Record a fresh scan so the staleness window would normally exclude it.
	ver := postgres.Versions{DBVersion: "db1", ScannerVersion: "gv1", CanonicalizerVersion: "c1"}
	if err := st.ApplyScan(ctx, sb, "grype", ver, nil); err != nil {
		t.Fatalf("apply scan: %v", err)
	}
	due, err := st.ListScannableSBOMs(ctx, time.Hour, grypeOnly)
	if err != nil {
		t.Fatalf("list scannable: %v", err)
	}
	if containsSBOM(due, sb.ID) {
		t.Fatal("freshly scanned SBOM should not be due under a 1h window")
	}

	// Force a rescan → now due despite the fresh scan.
	if err := st.AdminRequestRescan(ctx, sb.ID); err != nil {
		t.Fatalf("request rescan: %v", err)
	}
	due, _ = st.ListScannableSBOMs(ctx, time.Hour, grypeOnly)
	if !containsSBOM(due, sb.ID) {
		t.Fatal("after force-rescan the SBOM should be due")
	}

	// The scan loop clears the marker after all scanners run → no longer due.
	if err := st.ClearRescanRequested(ctx, sb.ID); err != nil {
		t.Fatalf("clear rescan: %v", err)
	}
	due, _ = st.ListScannableSBOMs(ctx, time.Hour, grypeOnly)
	if containsSBOM(due, sb.ID) {
		t.Error("after clearing the marker the fresh SBOM should not be due")
	}
}

func containsSBOM(list []*postgres.SBOM, id string) bool {
	for _, s := range list {
		if s.ID == id {
			return true
		}
	}
	return false
}

package server_test

import (
	"bytes"
	"context"
	"mime/multipart"
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

type roleMatrixRoute struct {
	name       string
	method     string
	path       string
	capability account.Capability
	vex        bool
}

func TestRoleMatrix(t *testing.T) {
	srv, st := testServer(t)
	h := srv.Handler()

	routes := []roleMatrixRoute{
		{"overview", http.MethodGet, "/overview", account.ReadAccount, false},
		{"search", http.MethodGet, "/search", account.ReadAccount, false},
		{"dashboard", http.MethodGet, "/dashboard", account.ReadAccount, false},
		{"trends", http.MethodGet, "/trends", account.ReadAccount, false},
		{"image", http.MethodGet, "/images", account.ReadAccount, false},
		{"compare", http.MethodGet, "/compare", account.ReadAccount, false},
		{"sbom", http.MethodGet, "/sboms/missing", account.ReadAccount, false},
		{"archive sbom", http.MethodPost, "/sboms/missing/archive", account.WriteEvidence, false},
		{"archive image", http.MethodPost, "/images/archive", account.WriteEvidence, false},
		{"cves", http.MethodGet, "/cves", account.ReadAccount, false},
		{"work", http.MethodGet, "/work", account.ReadAccount, false},
		{"cve", http.MethodGet, "/cves/CVE-MISSING", account.ReadAccount, false},
		{"licenses", http.MethodGet, "/licenses", account.ReadAccount, false},
		{"license family", http.MethodGet, "/licenses/family", account.ReadAccount, false},
		{"alerts", http.MethodGet, "/alerts", account.ReadAccount, false},
		{"alert", http.MethodGet, "/alerts/00000000-0000-0000-0000-000000000000", account.ReadAccount, false},
		{"mark alert read", http.MethodPost, "/alerts/00000000-0000-0000-0000-000000000000/read", account.WritePersonal, false},
		{"license policy", http.MethodPost, "/settings/license-policy", account.ManageSettings, false},
		{"docs", http.MethodGet, "/docs", account.ReadAccount, false},
		{"legacy docs", http.MethodGet, "/submit", account.ReadAccount, false},
		{"upload vex", http.MethodPost, "/vex/upload", account.WriteEvidence, true},
		{"tokens", http.MethodGet, "/tokens", account.ManageCredentials, false},
		{"create token", http.MethodPost, "/tokens", account.ManageCredentials, false},
		{"revoke token", http.MethodPost, "/tokens/00000000-0000-0000-0000-000000000000/revoke", account.ManageCredentials, false},
		{"minimum severity", http.MethodPost, "/settings/min-severity", account.ManageSettings, false},
		{"alert policy", http.MethodPost, "/settings/alerts", account.ManageSettings, false},
		{"account settings", http.MethodGet, "/account/settings", account.ManageSettings, false},
		{"account name", http.MethodPost, "/account/settings/name", account.ManageSettings, false},
		{"account members", http.MethodGet, "/account/members", account.ManageMembers, false},
		{"member role", http.MethodPost, "/account/members/00000000-0000-0000-0000-000000000000/role", account.ManageMembers, false},
		{"member revoke", http.MethodPost, "/account/members/00000000-0000-0000-0000-000000000000/revoke", account.ManageMembers, false},
	}

	for _, role := range []account.Role{account.RoleAdmin, account.RoleEditor, account.RoleReader} {
		t.Run(string(role), func(t *testing.T) {
			session := seedRoleSession(t, st, role)
			for _, route := range routes {
				t.Run(route.name, func(t *testing.T) {
					req := roleMatrixRequest(t, route, session)
					rec := httptest.NewRecorder()
					h.ServeHTTP(rec, req)

					if role.Can(route.capability) {
						if rec.Code == http.StatusForbidden {
							t.Fatalf("%s %s as %s = 403, want capability %s allowed: %s",
								route.method, route.path, role, route.capability, rec.Body.String())
						}
						if rec.Code == http.StatusFound && strings.HasPrefix(rec.Header().Get("Location"), "/accounts") {
							t.Fatalf("%s %s as %s redirected unavailable", route.method, route.path, role)
						}
						return
					}
					if rec.Code != http.StatusForbidden {
						t.Fatalf("%s %s as %s = %d, want 403 for missing %s: %s",
							route.method, route.path, role, rec.Code, route.capability, rec.Body.String())
					}
				})
			}
		})
	}
}

func TestRoleMatrixManageMembersCapability(t *testing.T) {
	st := testPostgresStore(t)
	for _, role := range []account.Role{account.RoleAdmin, account.RoleEditor, account.RoleReader} {
		t.Run(string(role), func(t *testing.T) {
			session := seedRoleSession(t, st, role)
			called := false
			h := middleware.RequireUser(st, "/")(
				middleware.RequireAccount(st, "/accounts")(
					middleware.RequireCapability(account.ManageMembers)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						called = true
						w.WriteHeader(http.StatusNoContent)
					})),
				),
			)
			req := httptest.NewRequest(http.MethodPost, "/account/members", nil)
			req.AddCookie(session)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if role == account.RoleAdmin {
				if rec.Code != http.StatusNoContent || !called {
					t.Fatalf("admin members capability = %d, called %v; want 204, true", rec.Code, called)
				}
				return
			}
			if rec.Code != http.StatusForbidden || called {
				t.Fatalf("%s members capability = %d, called %v; want 403, false", role, rec.Code, called)
			}
		})
	}
}

func TestRoleMatrixMutationEffects(t *testing.T) {
	srv, st := testServer(t)
	h := srv.Handler()
	ctx := context.Background()

	t.Run("write personal marks the current account alert", func(t *testing.T) {
		session := seedRoleSession(t, st, account.RoleReader)
		accountID := selectedAccountID(t, st, session)
		sbom := seedLabeledSBOM(t, st, accountID, "personal-effect")
		alertID := seedBrowserAlert(t, st, accountID, sbom, "CVE-2026-5101")
		tokensBefore := accountTokenCount(t, st, accountID)
		actor := sessionUserActor(t, st, session)

		rec := postRoleMutation(t, h, session, "/alerts/"+alertID+"/read", nil)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/alerts/"+alertID {
			t.Fatalf("mark alert read = %d location %q, want 303 alert detail: %s",
				rec.Code, rec.Header().Get("Location"), rec.Body.String())
		}
		var receiptRead, compatibilityRead bool
		if err := st.DB().QueryRowContext(ctx,
			`SELECT EXISTS(
				SELECT 1 FROM devradar_alert_receipt
				WHERE account_id=$1 AND alert_id=$2 AND user_id=$3
			),read_at IS NOT NULL
			FROM devradar_alert WHERE tenant_id=$1 AND id=$2`,
			accountID, alertID, actor.UserID).Scan(&receiptRead, &compatibilityRead); err != nil {
			t.Fatalf("read alert effect: %v", err)
		}
		if !receiptRead || compatibilityRead {
			t.Fatalf("alert receipt/compatibility read = %v/%v, want true/false", receiptRead, compatibilityRead)
		}
		if got := accountTokenCount(t, st, accountID); got != tokensBefore {
			t.Fatalf("mark alert read changed token count from %d to %d", tokensBefore, got)
		}
	})

	t.Run("write evidence archives only the SBOM", func(t *testing.T) {
		session := seedRoleSession(t, st, account.RoleEditor)
		accountID := selectedAccountID(t, st, session)
		sbom := seedLabeledSBOM(t, st, accountID, "archive-effect")
		tokensBefore := accountTokenCount(t, st, accountID)

		rec := postRoleMutation(t, h, session, "/sboms/"+sbom.ID+"/archive", nil)
		if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "msg=sbom_archived") {
			t.Fatalf("archive SBOM = %d location %q, want 303 archive message: %s",
				rec.Code, rec.Header().Get("Location"), rec.Body.String())
		}
		var status string
		if err := st.DB().QueryRowContext(ctx,
			`SELECT status FROM devradar_sbom WHERE tenant_id=$1 AND id=$2`,
			accountID, sbom.ID).Scan(&status); err != nil {
			t.Fatalf("read archive effect: %v", err)
		}
		if status != "archived" {
			t.Fatalf("SBOM status = %q, want archived", status)
		}
		if got := accountTokenCount(t, st, accountID); got != tokensBefore {
			t.Fatalf("archive SBOM changed token count from %d to %d", tokensBefore, got)
		}
	})

	t.Run("manage settings changes only threshold", func(t *testing.T) {
		session := seedRoleSession(t, st, account.RoleAdmin)
		accountID := selectedAccountID(t, st, session)
		tokensBefore := accountTokenCount(t, st, accountID)

		rec := postRoleMutation(t, h, session, "/settings/min-severity", url.Values{"min_severity": {"high"}})
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/tokens" {
			t.Fatalf("set threshold = %d location %q, want 303 /tokens: %s",
				rec.Code, rec.Header().Get("Location"), rec.Body.String())
		}
		var severity string
		if err := st.DB().QueryRowContext(ctx,
			`SELECT min_severity FROM devradar_tenant WHERE id=$1`, accountID).Scan(&severity); err != nil {
			t.Fatalf("read threshold effect: %v", err)
		}
		if severity != "high" {
			t.Fatalf("minimum severity = %q, want high", severity)
		}
		if got := accountTokenCount(t, st, accountID); got != tokensBefore {
			t.Fatalf("set threshold changed token count from %d to %d", tokensBefore, got)
		}
	})

	t.Run("manage credentials creates and revokes only the selected token", func(t *testing.T) {
		session := seedRoleSession(t, st, account.RoleAdmin)
		accountID := selectedAccountID(t, st, session)
		sbom := seedLabeledSBOM(t, st, accountID, "credential-effect")
		alertID := seedBrowserAlert(t, st, accountID, sbom, "CVE-2026-5102")
		actor := sessionUserActor(t, st, session)
		before, err := st.ListAPITokens(ctx, accountID, actor)
		if err != nil {
			t.Fatalf("list tokens before create: %v", err)
		}

		create := postRoleMutation(t, h, session, "/tokens", url.Values{"name": {"effect-created"}})
		if create.Code != http.StatusSeeOther || create.Header().Get("Location") != "/tokens" {
			t.Fatalf("create token = %d location %q, want 303 /tokens: %s",
				create.Code, create.Header().Get("Location"), create.Body.String())
		}
		afterCreate, err := st.ListAPITokens(ctx, accountID, actor)
		if err != nil {
			t.Fatalf("list tokens after create: %v", err)
		}
		if len(afterCreate) != len(before)+1 || afterCreate[0].Name != "effect-created" {
			t.Fatalf("tokens after create = %#v, want one new effect-created token", afterCreate)
		}
		createdID := afterCreate[0].ID

		revoke := postRoleMutation(t, h, session, "/tokens/"+createdID+"/revoke", nil)
		if revoke.Code != http.StatusSeeOther || revoke.Header().Get("Location") != "/tokens" {
			t.Fatalf("revoke token = %d location %q, want 303 /tokens: %s",
				revoke.Code, revoke.Header().Get("Location"), revoke.Body.String())
		}
		afterRevoke, err := st.ListAPITokens(ctx, accountID, actor)
		if err != nil {
			t.Fatalf("list tokens after revoke: %v", err)
		}
		if len(afterRevoke) != len(before) {
			t.Fatalf("token count after revoke = %d, want %d", len(afterRevoke), len(before))
		}
		for _, token := range afterRevoke {
			if token.ID == createdID {
				t.Fatal("revoked token still exists")
			}
		}
		var read bool
		if err := st.DB().QueryRowContext(ctx,
			`SELECT read_at IS NOT NULL FROM devradar_alert WHERE tenant_id=$1 AND id=$2`,
			accountID, alertID).Scan(&read); err != nil {
			t.Fatalf("read unrelated alert state: %v", err)
		}
		if read {
			t.Fatal("credential mutations marked an unrelated alert read")
		}
	})
}

func seedRoleSession(t *testing.T, st *postgres.Store, role account.Role) *http.Cookie {
	t.Helper()
	accountID, _ := seedTenantToken(t, st)
	userID := seedLegacyUser(t, st, accountID)
	if _, err := st.DB().ExecContext(context.Background(), `
		UPDATE devradar_account_member SET role=$3
		WHERE account_id=$1 AND user_id=$2`, accountID, userID, role); err != nil {
		t.Fatalf("set %s membership: %v", role, err)
	}
	raw, err := st.CreateSession(context.Background(), userID, &accountID, time.Hour)
	if err != nil {
		t.Fatalf("create %s session: %v", role, err)
	}
	return &http.Cookie{Name: middleware.SessionCookieName(), Value: raw}
}

func selectedAccountID(t *testing.T, st *postgres.Store, sessionCookie *http.Cookie) string {
	t.Helper()
	session, err := st.ValidateSession(context.Background(), sessionCookie.Value)
	if err != nil {
		t.Fatalf("validate role session: %v", err)
	}
	if session.ActiveAccountID == nil {
		t.Fatal("role session has no selected account")
	}
	return *session.ActiveAccountID
}

func accountTokenCount(t *testing.T, st *postgres.Store, accountID string) int {
	t.Helper()
	var count int
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT count(*) FROM devradar_api_token WHERE tenant_id=$1`, accountID).Scan(&count); err != nil {
		t.Fatalf("count account tokens: %v", err)
	}
	return count
}

func sessionUserActor(t *testing.T, st *postgres.Store, sessionCookie *http.Cookie) account.Actor {
	t.Helper()
	session, err := st.ValidateSession(context.Background(), sessionCookie.Value)
	if err != nil {
		t.Fatalf("validate role session actor: %v", err)
	}
	return account.Actor{Kind: account.ActorUser, UserID: session.User.ID}
}

func postRoleMutation(t *testing.T, h http.Handler, session *http.Cookie, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	token, err := middleware.GenerateCSRFToken()
	if err != nil {
		t.Fatalf("generate mutation CSRF token: %v", err)
	}
	if form == nil {
		form = url.Values{}
	}
	form.Set("csrf_token", token)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName(), Value: token})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func roleMatrixRequest(t *testing.T, route roleMatrixRoute, session *http.Cookie) *http.Request {
	t.Helper()
	token, err := middleware.GenerateCSRFToken()
	if err != nil {
		t.Fatalf("generate CSRF token: %v", err)
	}
	var req *http.Request
	if route.vex {
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		if err := writer.WriteField("csrf_token", token); err != nil {
			t.Fatalf("write multipart CSRF: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close multipart: %v", err)
		}
		req = httptest.NewRequest(route.method, route.path, &body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
	} else {
		form := url.Values{"csrf_token": {token}}
		switch route.path {
		case "/settings/min-severity", "/settings/alerts":
			form.Set("min_severity", "invalid")
		}
		req = httptest.NewRequest(route.method, route.path, strings.NewReader(form.Encode()))
		if route.method == http.MethodPost {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	req.AddCookie(session)
	req.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName(), Value: token})
	return req
}

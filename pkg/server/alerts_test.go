package server_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/thingzio/devradar/pkg/data/postgres"
)

func TestAlertSettings(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	otherTenantID, _ := seedTenantToken(t, st)
	seedLabeledSBOM(t, st, tenantID, "prod")
	seedLabeledSBOM(t, st, otherTenantID, "foreign")
	session := seedSession(t, st, tenantID)
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/tokens", nil)
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Browser alerts") ||
		!strings.Contains(rec.Body.String(), "Email and webhook delivery can be added later") {
		t.Fatalf("GET /tokens = %d body=%s", rec.Code, rec.Body.String())
	}

	csrfCookie, token := csrfFor(t, h, session, "/tokens")
	form := url.Values{
		"csrf_token":          {token},
		"enabled":             {"on"},
		"min_severity":        {"high"},
		"alert_kev":           {"on"},
		"alert_fix_available": {"on"},
		"include_image":       {"on"},
		"labels":              {"prod", "foreign"},
	}
	req = httptest.NewRequest(http.MethodPost, "/settings/alerts", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	req.AddCookie(csrfCookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/tokens?alerts=saved" {
		t.Fatalf("POST /settings/alerts = %d location=%q body=%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	policy, err := st.EnsureAlertPolicy(context.Background(), tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if !policy.Enabled || policy.MinSeverity != "high" || !policy.AlertKEV ||
		!policy.AlertFixAvailable || !policy.IncludeImage || policy.IncludeDB ||
		len(policy.Labels) != 1 || policy.Labels[0] != "prod" {
		t.Fatalf("saved policy = %+v", policy)
	}

	bad := url.Values{"csrf_token": {token}, "enabled": {"on"}, "min_severity": {"mystery"}}
	req = httptest.NewRequest(http.MethodPost, "/settings/alerts", strings.NewReader(bad.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	req.AddCookie(csrfCookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid severity = %d, want 400", rec.Code)
	}
}

func TestAlertPages(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	otherTenantID, _ := seedTenantToken(t, st)
	sb := seedLabeledSBOM(t, st, tenantID, "prod")
	otherSB := seedLabeledSBOM(t, st, otherTenantID, "other")
	alertID := seedBrowserAlert(t, st, tenantID, sb, "CVE-2026-3001")
	otherAlertID := seedBrowserAlert(t, st, otherTenantID, otherSB, "CVE-2026-9999")
	session := seedSession(t, st, tenantID)
	otherSession := seedSession(t, st, otherTenantID)
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/alerts", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("unauthenticated alerts = %d, want 302", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/alerts", nil)
	req.AddCookie(session)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "CVE-2026-3001") ||
		strings.Contains(rec.Body.String(), "CVE-2026-9999") {
		t.Fatalf("GET /alerts = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/alerts/"+alertID, nil)
	req.AddCookie(session)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "New vulnerability") ||
		!strings.Contains(rec.Body.String(), "CVE-2026-3001") {
		t.Fatalf("GET alert detail = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/alerts/"+alertID, nil)
	req.AddCookie(otherSession)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant detail = %d, want 404", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/alerts/"+otherAlertID, nil)
	req.AddCookie(session)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant other detail = %d, want 404", rec.Code)
	}

	csrfCookie, token := csrfFor(t, h, session, "/alerts/"+alertID)
	form := url.Values{"csrf_token": {token}}
	for i := 0; i < 2; i++ {
		req = httptest.NewRequest(http.MethodPost, "/alerts/"+alertID+"/read", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(session)
		req.AddCookie(csrfCookie)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/alerts/"+alertID {
			t.Fatalf("mark read attempt %d = %d location=%q", i+1, rec.Code, rec.Header().Get("Location"))
		}
	}
	got, err := st.GetAlert(context.Background(), tenantID, alertID)
	if err != nil || got.ReadAt == nil {
		t.Fatalf("alert read state = %+v error=%v", got, err)
	}
}

func TestOverviewUnreadAlerts(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	otherTenantID, _ := seedTenantToken(t, st)
	sb := seedLabeledSBOM(t, st, tenantID, "overview")
	otherSB := seedLabeledSBOM(t, st, otherTenantID, "overview-other")
	for i := 0; i < 6; i++ {
		seedBrowserAlert(t, st, tenantID, sb, "CVE-2026-40"+string(rune('0'+i)))
	}
	seedBrowserAlert(t, st, otherTenantID, otherSB, "CVE-2026-4999")
	session := seedSession(t, st, tenantID)

	req := httptest.NewRequest(http.MethodGet, "/overview", nil)
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /overview = %d body=%s", rec.Code, body)
	}
	if got := strings.Count(body, `class="overview-alert`); got != 5 {
		t.Fatalf("overview alert count = %d, want 5", got)
	}
	if !strings.Contains(body, `href="/alerts"`) || strings.Contains(body, "CVE-2026-4999") {
		t.Fatalf("overview alert links/isolation body=%s", body)
	}
}

func seedLabeledSBOM(t *testing.T, st *postgres.Store, tenantID, label string) *postgres.SBOM {
	t.Helper()
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("random sbom id: %v", err)
	}
	id := hex.EncodeToString(random)
	sb := &postgres.SBOM{
		ID: id, TenantID: tenantID, ImageRef: "registry.test/" + label,
		Repository: "registry.test/" + label, Digest: "sha256:" + id,
		Format: "cyclonedx", PackageCount: 1, ObjectPath: "gs://test/" + id,
		Status: "active", Labels: []string{label},
	}
	if _, _, _, err := st.UpsertSBOM(context.Background(), sb); err != nil {
		t.Fatalf("seed labeled sbom: %v", err)
	}
	return sb
}

func seedBrowserAlert(t *testing.T, st *postgres.Store, tenantID string, sb *postgres.SBOM, cve string) string {
	t.Helper()
	policy, err := st.EnsureAlertPolicy(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("ensure alert policy: %v", err)
	}
	var id string
	err = st.DB().QueryRowContext(context.Background(), `
		INSERT INTO devradar_alert
		(tenant_id, policy_id, event_id, event_occurred_at, alert_kind, sbom_id,
		 repository, digest, finding_id, exposure, package, version, severity, score, cause)
		VALUES ($1,$2,nextval('devradar_finding_event_id_seq'),now(),'new_finding',$3,$4,$5,
		        $6,$7,'openssl','1.0.0','high',8.1,'db')
		RETURNING id`, tenantID, policy.ID, sb.ID, sb.Repository, sb.Digest,
		"finding-"+cve, cve).Scan(&id)
	if err != nil {
		t.Fatalf("seed browser alert: %v", err)
	}
	return id
}

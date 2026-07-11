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

func seedLabeledSBOM(t *testing.T, st *postgres.Store, tenantID, label string) {
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
}

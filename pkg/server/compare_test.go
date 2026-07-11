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
)

func TestComparePage(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	from := seedLabeledSBOM(t, st, tenantID, "compare")
	to := *from
	to.ID = randomHex(t, 32)
	to.Digest = "sha256:" + randomHex(t, 32)
	to.Version = "v2"
	if _, _, _, err := st.UpsertSBOM(context.Background(), &to); err != nil {
		t.Fatal(err)
	}
	seedWorkFinding(t, st, from, "grype", "old", "CVE-2026-7001", false)
	seedWorkFinding(t, st, &to, "grype", "new", "CVE-2026-7002", false)
	if _, err := st.DB().ExecContext(context.Background(),
		`UPDATE devradar_finding SET severity='critical' WHERE sbom_id=$1`, to.ID); err != nil {
		t.Fatal(err)
	}
	session := seedSession(t, st, tenantID)
	h := srv.Handler()

	path := "/compare?" + url.Values{"from": {from.ID}, "to": {to.ID}}.Encode()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "Regresses posture") ||
		!strings.Contains(body, "CVE-2026-7001") || !strings.Contains(body, "CVE-2026-7002") ||
		strings.Contains(strings.ToLower(body), "universally safe") {
		t.Fatalf("GET compare = %d body=%s", rec.Code, body)
	}

	req = httptest.NewRequest(http.MethodGet, "/images?repo="+url.QueryEscape(from.Repository), nil)
	req.AddCookie(session)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `action="/compare"`) {
		t.Fatalf("image compare form = %d body=%s", rec.Code, rec.Body.String())
	}

	otherTenantID, _ := seedTenantToken(t, st)
	otherSession := seedSession(t, st, otherTenantID)
	req = httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(otherSession)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant compare = %d, want 404", rec.Code)
	}
}

func randomHex(t *testing.T, bytes int) string {
	t.Helper()
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

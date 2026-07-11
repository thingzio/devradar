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
	"time"

	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
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
	baseTime := time.Now().UTC().Add(-2 * time.Hour)
	if _, err := st.DB().ExecContext(context.Background(), `
		UPDATE devradar_sbom SET generated_at=$2 WHERE id=$1`, from.ID, baseTime); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(context.Background(), `
		UPDATE devradar_sbom SET generated_at=$2 WHERE id=$1`, to.ID, baseTime.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	seedWorkFinding(t, st, from, "grype", "old", "CVE-2026-7001", false)
	seedWorkFinding(t, st, &to, "grype", "new", "CVE-2026-7002", false)
	if _, err := st.DB().ExecContext(context.Background(),
		`UPDATE devradar_finding SET severity='critical' WHERE sbom_id=$1`, to.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.SetLicensePolicy(context.Background(), tenantID, data.LicensePolicy{
		DeniedCategories: []data.LicenseCategory{data.CategoryStrongCopyleft},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSBOMPackages(context.Background(), from.ID, []data.PackageLicense{
		{Package: "changed-license", Version: "1", Licenses: []string{"MIT"}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSBOMPackages(context.Background(), to.ID, []data.PackageLicense{
		{Package: "changed-license", Version: "1", Licenses: []string{"GPL-3.0"}},
		{Package: "new-denied-license", Version: "1", Licenses: []string{"AGPL-3.0"}},
	}); err != nil {
		t.Fatal(err)
	}
	upgrade := *from
	upgrade.ID = randomHex(t, 32)
	upgrade.Digest = "sha256:" + randomHex(t, 32)
	upgrade.Version = "v3"
	upgrade.GeneratedAt = baseTime.Add(2 * time.Hour)
	if _, _, _, err := st.UpsertSBOM(context.Background(), &upgrade); err != nil {
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
		!strings.Contains(body, "License-policy regressions") ||
		!strings.Contains(body, "changed-license") || !strings.Contains(body, "new-denied-license") ||
		!strings.Contains(body, "newer tracked digest with fewer relevant findings") ||
		!strings.Contains(body, url.QueryEscape(to.ID)) || !strings.Contains(body, url.QueryEscape(upgrade.ID)) ||
		strings.Contains(strings.ToLower(body), "universally safe") {
		t.Fatalf("GET compare = %d body=%s", rec.Code, body)
	}

	path = "/compare?" + url.Values{"from": {to.ID}, "to": {upgrade.ID}}.Encode()
	req = httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(session)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "newer tracked digest with fewer relevant findings") {
		t.Fatalf("newest comparison recommendation = %d body=%s", rec.Code, rec.Body.String())
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

func TestComparePage_UpgradeGuidanceDoesNotLeakForeignOrOlderGenerations(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	baseline := seedLabeledSBOM(t, st, tenantID, "upgrade-isolation")
	baseTime := time.Now().UTC()
	if _, err := st.DB().ExecContext(context.Background(),
		`UPDATE devradar_sbom SET generated_at=$2 WHERE id=$1`, baseline.ID, baseTime); err != nil {
		t.Fatal(err)
	}
	seedWorkFinding(t, st, baseline, "grype", "baseline", "CVE-2026-8201", false)
	older := *baseline
	older.ID, older.Digest, older.Version, older.GeneratedAt = randomHex(t, 32), "sha256:"+randomHex(t, 32), "older", baseTime.Add(-time.Hour)
	if _, _, _, err := st.UpsertSBOM(context.Background(), &older); err != nil {
		t.Fatal(err)
	}

	otherTenantID, _ := seedTenantToken(t, st)
	foreign := &postgres.SBOM{
		ID: randomHex(t, 32), TenantID: otherTenantID, ImageRef: baseline.Repository + ":foreign",
		Repository: baseline.Repository, Version: "foreign", Digest: "sha256:" + randomHex(t, 32),
		Format: "cyclonedx", ObjectPath: "gs://test/foreign", Status: "active", GeneratedAt: baseTime.Add(time.Hour),
	}
	if _, _, _, err := st.UpsertSBOM(context.Background(), foreign); err != nil {
		t.Fatal(err)
	}

	session := seedSession(t, st, tenantID)
	path := "/compare?" + url.Values{"from": {older.ID}, "to": {baseline.ID}}.Encode()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || strings.Contains(body, "newer tracked digest with fewer relevant findings") ||
		strings.Contains(body, foreign.Digest) {
		t.Fatalf("isolated upgrade guidance = %d body=%s", rec.Code, body)
	}
}

func TestComparePage_ArchivedEvidenceSurvivesRecommendationFailure(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	from := seedLabeledSBOM(t, st, tenantID, "compare-archived")
	from.Version = "v1"
	to := *from
	to.ID = randomHex(t, 32)
	to.Digest = "sha256:" + randomHex(t, 32)
	to.Version = "v2"
	if _, _, _, err := st.UpsertSBOM(context.Background(), &to); err != nil {
		t.Fatal(err)
	}
	seedWorkFinding(t, st, from, "grype", "archived-route-old", "CVE-2026-7301", false)
	seedWorkFinding(t, st, &to, "grype", "archived-route-new", "CVE-2026-7302", false)
	if _, err := st.DB().ExecContext(context.Background(),
		`UPDATE devradar_sbom SET status='archived' WHERE id IN ($1,$2)`, from.ID, to.ID); err != nil {
		t.Fatal(err)
	}

	path := "/compare?" + url.Values{"from": {from.ID}, "to": {to.ID}}.Encode()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(seedSession(t, st, tenantID))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "Digest comparison") ||
		!strings.Contains(body, "CVE-2026-7301") || !strings.Contains(body, "CVE-2026-7302") ||
		!strings.Contains(body, "KEV → critical → high → medium → low → total") {
		t.Fatalf("archived comparison page = %d body=%s", rec.Code, body)
	}
	if strings.Contains(body, "newer tracked digest with fewer relevant findings") {
		t.Fatalf("archived comparison rendered active-only recommendation: %s", body)
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

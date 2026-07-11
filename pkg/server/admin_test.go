package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
	"github.com/thingzio/devradar/pkg/tenant"
)

// tenantEmail reads a seeded tenant's email so a test can add it to the admin
// allowlist.
func tenantEmail(t *testing.T, st *postgres.Store, id string) string {
	t.Helper()
	tn, err := tenant.GetTenant(context.Background(), st.DB(), id)
	if err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	return tn.Email
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

// TestAdmin_AdminSeesDashboard verifies an allowlisted tenant reaches the
// dashboard (200).
func TestAdmin_AdminSeesDashboard(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	t.Setenv("DEVRADAR_ADMIN_USERS", tenantEmail(t, st, tenantID))
	h := srv.Handler()
	cookie := seedSession(t, st, tenantID)

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin /admin: status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Platform") {
		t.Error("dashboard body should contain the Platform heading")
	}
}

// TestAdmin_CSRFRequired verifies a mutating POST without a valid CSRF token is
// rejected 403, and the same POST with matching cookie+field succeeds (303).
func TestAdmin_CSRFRequired(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	t.Setenv("DEVRADAR_ADMIN_USERS", tenantEmail(t, st, tenantID))
	h := srv.Handler()
	cookie := seedSession(t, st, tenantID)

	target, _ := seedTenantToken(t, st) // the tenant we mutate

	// No CSRF token → 403.
	body := "plan=paid"
	req := httptest.NewRequest(http.MethodPost, "/admin/tenant/"+target+"/plan", strings.NewReader(body))
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
	req2 := httptest.NewRequest(http.MethodPost, "/admin/tenant/"+target+"/plan",
		strings.NewReader("plan=paid&csrf_token="+tok))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.AddCookie(cookie)
	req2.AddCookie(&http.Cookie{Name: middleware.CSRFCookieName(), Value: tok})
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusSeeOther {
		t.Fatalf("POST with CSRF: status = %d, want 303", rec2.Code)
	}
	tn, _ := tenant.GetTenant(context.Background(), st.DB(), target)
	if tn.Plan != "paid" {
		t.Errorf("plan = %q, want paid (mutation should have applied)", tn.Plan)
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

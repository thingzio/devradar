package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDocsPage verifies the renamed Docs page renders its table of contents and
// concept sections, and that the historical /submit path redirects to it.
func TestDocsPage(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)

	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	req.AddCookie(seedSession(t, st, tenantID))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /docs = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"On this page",        // TOC
		"How DevRadar works",  // concept section
		`id="accuracy"`,       // accuracy anchor
		`id="reading"`,        // reading results anchor
		`id="licenses"`,       // licenses anchor
		`id="trust"`,          // trust anchor
		`id="faq"`,            // faq anchor
		"Submit with the CLI", // submission guide preserved
		"devradarctl",         // CLI still documented
		`class="tab active" aria-current="page">Docs`, // nav tab renamed + active
	} {
		if !strings.Contains(body, want) {
			t.Errorf("docs page missing %q", want)
		}
	}

	// /submit still resolves — redirected to /docs.
	sreq := httptest.NewRequest(http.MethodGet, "/submit", nil)
	sreq.AddCookie(seedSession(t, st, tenantID))
	srec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(srec, sreq)
	if srec.Code != http.StatusMovedPermanently {
		t.Fatalf("GET /submit = %d, want 301", srec.Code)
	}
	if loc := srec.Header().Get("Location"); loc != "/docs" {
		t.Fatalf("GET /submit Location = %q, want /docs", loc)
	}
}

// TestLicenseFamilyPage verifies the family drill-down lists the packages
// carrying the queried license family (scoped to the tenant), and that a digest
// "license" never surfaces as its own family.
func TestLicenseFamilyPage(t *testing.T) {
	srv, st := testServer(t)
	ctx := context.Background()
	tenantID, _ := seedTenantToken(t, st)
	foreignID, _ := seedTenantToken(t, st)
	sb := seedLabeledSBOM(t, st, tenantID, "family-page")
	foreignSB := seedLabeledSBOM(t, st, foreignID, "foreign-family")

	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_sbom_package (sbom_id, package, version, licenses)
		VALUES
			($1, 'gpl-pkg', '1.0', ARRAY['GPL-3.0-only']),
			($1, 'mit-pkg', '2.0', ARRAY['MIT']),
			($1, 'digest-pkg', '3.0', ARRAY['sha256:0b7b3f1644af45c0e1279e995e5daa5b465997235c16bc86c83dcdf3c3b88b05']),
			($2, 'foreign-gpl', '9.9', ARRAY['GPL-2.0-only'])`,
		sb.ID, foreignSB.ID); err != nil {
		t.Fatalf("seed packages: %v", err)
	}

	get := func(path string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(seedSession(t, st, tenantID))
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d body=%s", path, rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}

	// GPL family lists this tenant's GPL package, not the foreign tenant's.
	body := get("/licenses/family?family=GPL")
	if !strings.Contains(body, "gpl-pkg") {
		t.Errorf("GPL family page missing gpl-pkg")
	}
	if strings.Contains(body, "mit-pkg") {
		t.Errorf("GPL family page leaked mit-pkg")
	}
	if strings.Contains(body, "foreign-gpl") {
		t.Errorf("GPL family page leaked foreign tenant package")
	}

	// The Licenses page must never show a sha256 digest as a family label.
	lic := get("/licenses")
	if strings.Contains(lic, "sha256:") {
		t.Errorf("licenses page leaked a digest as a license family")
	}
}

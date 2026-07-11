package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thingzio/devradar/pkg/data/postgres"
)

func TestWorkQueue(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	otherTenantID, _ := seedTenantToken(t, st)
	sb := seedLabeledSBOM(t, st, tenantID, "work")
	otherSB := seedLabeledSBOM(t, st, otherTenantID, "work-other")
	seedWorkFinding(t, st, sb, "grype", "finding-work", "CVE-2026-5001", true)
	seedWorkFinding(t, st, sb, "trivy", "finding-work", "CVE-2026-5001", true)
	seedWorkFinding(t, st, otherSB, "grype", "finding-other", "CVE-2026-5999", false)
	session := seedSession(t, st, tenantID)

	req := httptest.NewRequest(http.MethodGet, "/work", nil)
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "What should I fix?") ||
		!strings.Contains(body, "CVE-2026-5001") || !strings.Contains(body, "Fix available") ||
		!strings.Contains(body, "2 scanners agree") || strings.Contains(body, "CVE-2026-5999") {
		t.Fatalf("GET /work = %d body=%s", rec.Code, body)
	}
}

func TestWorkQueue_ShowsPartialAndFullVEXSuppression(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	first := seedLabeledSBOM(t, st, tenantID, "work-vex-first")
	second := seedLabeledSBOM(t, st, tenantID, "work-vex-second")
	seedWorkFinding(t, st, first, "grype", "partial-first", "CVE-2026-5101", false)
	seedWorkFinding(t, st, second, "grype", "partial-second", "CVE-2026-5101", false)
	seedWorkFinding(t, st, first, "grype", "fully-suppressed", "CVE-2026-5102", false)
	seedWorkVEX(t, st, tenantID, first.Digest, "CVE-2026-5101", "not_affected")
	seedWorkVEX(t, st, tenantID, first.Digest, "CVE-2026-5102", "fixed")

	req := httptest.NewRequest(http.MethodGet, "/work", nil)
	req.AddCookie(seedSession(t, st, tenantID))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /work = %d body=%s", rec.Code, body)
	}
	partial := workArticle(t, body, "CVE-2026-5101")
	if strings.Contains(partial, `class="work-item vexed`) || !strings.Contains(partial, "VEX suppresses some tracked occurrences") {
		t.Fatalf("partial VEX work item lacks visible non-dimmed context: %s", partial)
	}
	full := workArticle(t, body, "CVE-2026-5102")
	if !strings.Contains(full, `class="work-item vexed`) || !strings.Contains(full, "VEX suppresses all tracked occurrences") {
		t.Fatalf("fully suppressed work item lacks visible de-emphasis context: %s", full)
	}
}

func workArticle(t *testing.T, body, cve string) string {
	t.Helper()
	start := strings.Index(body, `id="work-`+cve+`"`)
	if start < 0 {
		t.Fatalf("work item %s not found in %s", cve, body)
	}
	start = strings.LastIndex(body[:start], "<article")
	if start < 0 {
		t.Fatalf("work item %s start tag not found in %s", cve, body)
	}
	end := strings.Index(body[start:], "</article>")
	if end < 0 {
		t.Fatalf("work item %s markup not found in %s", cve, body)
	}
	return body[start : start+end+len("</article>")]
}

func seedWorkFinding(t *testing.T, st *postgres.Store, sb *postgres.SBOM, scanner, findingID, cve string, fixed bool) {
	t.Helper()
	if _, err := st.DB().ExecContext(context.Background(), `
		INSERT INTO devradar_finding
		(sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
		VALUES ($1,$2,$3,$4,'openssl','1.0','high',8.1,$5)`,
		sb.ID, scanner, findingID, cve, fixed); err != nil {
		t.Fatalf("seed work finding: %v", err)
	}
}

func seedWorkVEX(t *testing.T, st *postgres.Store, tenantID, digest, cve, status string) {
	t.Helper()
	var documentID string
	if err := st.DB().QueryRowContext(context.Background(), `
		INSERT INTO devradar_vex_document (tenant_id, document)
		VALUES ($1, '{}'::jsonb) RETURNING id`, tenantID).Scan(&documentID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(context.Background(), `
		INSERT INTO devradar_vex_statement
		(tenant_id, document_id, product_digest, vulnerability, status)
		VALUES ($1,$2,$3,$4,$5)`, tenantID, documentID, digest, cve, status); err != nil {
		t.Fatal(err)
	}
}

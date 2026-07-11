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

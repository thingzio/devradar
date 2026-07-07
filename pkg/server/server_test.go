package server_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/gcs"
	"github.com/thingzio/devradar/pkg/middleware"
	"github.com/thingzio/devradar/pkg/server"
	"github.com/thingzio/devradar/pkg/tenant"
)

// seedSession mints a UI session cookie for a tenant so tests can exercise
// authenticated browser routes (not just API-token routes).
func seedSession(t *testing.T, st *postgres.Store, tenantID string) *http.Cookie {
	t.Helper()
	raw, err := tenant.CreateSession(context.Background(), st.DB(), tenantID, time.Hour)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return &http.Cookie{Name: middleware.SessionCookieName(), Value: raw}
}

func testServer(t *testing.T) (*server.Server, *postgres.Store) {
	t.Helper()
	st, err := postgres.NewFromEnv(context.Background())
	if err != nil {
		t.Skipf("skipping (no database): %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	// OAuth nil → API-only; local blob store under a temp dir.
	srv := server.New(st, gcs.LocalStore{Dir: t.TempDir()}, nil, server.Options{Version: "test"})
	return srv, st
}

func seedTenantToken(t *testing.T, st *postgres.Store) (tenantID, token string) {
	t.Helper()
	ctx := context.Background()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"u"+hex.EncodeToString(b)+"@example.com").Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	tok, err := tenant.CreateAPIToken(ctx, st.DB(), tenantID, "test")
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	return tenantID, tok
}

func TestIngest_RequiresAuth(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodPost, "/v1/sboms", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no auth: status = %d, want 401", rec.Code)
	}
}

func TestIngest_RejectsBadBody(t *testing.T) {
	srv, st := testServer(t)
	_, tok := seedTenantToken(t, st)
	h := srv.Handler()

	cases := []struct {
		name, body string
		want       int
	}{
		{"not json", `nope`, http.StatusBadRequest},
		{"missing sbom", `{}`, http.StatusBadRequest},
		{"bad base64", `{"sbom":"!!!!"}`, http.StatusBadRequest},
		{"not an sbom", `{"sbom":"` + base64.StdEncoding.EncodeToString([]byte(`{"x":1}`)) + `"}`, http.StatusUnprocessableEntity},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/sboms", strings.NewReader(c.body))
			req.Header.Set("Authorization", "Bearer "+tok)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != c.want {
				t.Errorf("status = %d, want %d (body: %s)", rec.Code, c.want, rec.Body.String())
			}
		})
	}
}

// TestSecurityHeaders asserts the hardening headers (incl. CSP) are present on
// every response — they're set in the outermost middleware, so even /health has them.
func TestSecurityHeaders(t *testing.T) {
	srv, _ := testServer(t)
	h := srv.Handler()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, must := range []string{"default-src 'self'", "script-src 'self'", "object-src 'none'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, must) {
			t.Errorf("CSP missing %q; got %q", must, csp)
		}
	}
}

// TestIngest_OversizedBody413 verifies an over-cap request body is rejected with
// 413 (MaxBytesReader), not silently truncated into a 400 bad-JSON.
func TestIngest_OversizedBody413(t *testing.T) {
	srv, st := testServer(t)
	_, tok := seedTenantToken(t, st)
	h := srv.Handler()

	// Just over the (maxSBOMBytes*4/3)+1024 body cap (~26.7 MiB). Content is
	// irrelevant — the reader trips the cap before any decode.
	huge := strings.Repeat("A", (20<<20)*4/3+1024+4096)
	req := httptest.NewRequest(http.MethodPost, "/v1/sboms", strings.NewReader(`{"sbom":"`+huge+`"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
}

func TestIngest_AndRead(t *testing.T) {
	srv, st := testServer(t)
	_, tok := seedTenantToken(t, st)
	h := srv.Handler()

	raw, err := os.ReadFile("../sbom/testdata/redis.syft.cdx.json")
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	body, _ := json.Marshal(map[string]string{"sbom": base64.StdEncoding.EncodeToString(raw)})

	// Submit.
	req := httptest.NewRequest(http.MethodPost, "/v1/sboms", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("submit status = %d, want 202 (%s)", rec.Code, rec.Body.String())
	}
	var sub struct {
		SBOMID   string `json:"sbom_id"`
		Digest   string `json:"digest"`
		Existing bool   `json:"existing"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &sub)
	if sub.SBOMID == "" || !strings.HasPrefix(sub.Digest, "sha256:") {
		t.Fatalf("unexpected submit response: %s", rec.Body.String())
	}

	// Resubmit → existing.
	req2 := httptest.NewRequest(http.MethodPost, "/v1/sboms", strings.NewReader(string(body)))
	req2.Header.Set("Authorization", "Bearer "+tok)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	var sub2 struct {
		Existing bool `json:"existing"`
	}
	_ = json.Unmarshal(rec2.Body.Bytes(), &sub2)
	if !sub2.Existing {
		t.Errorf("resubmit should report existing:true")
	}

	// List images (grouped by repository) includes the image's repository.
	req3 := httptest.NewRequest(http.MethodGet, "/v1/images", nil)
	req3.Header.Set("Authorization", "Bearer "+tok)
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK || !strings.Contains(rec3.Body.String(), `"repository":"redis"`) {
		t.Errorf("images should include repository redis, got %s", rec3.Body.String())
	}

	// The per-image SBOM list (CUJ-2) returns this SBOM under its repository.
	req4 := httptest.NewRequest(http.MethodGet, "/v1/images/sboms?repo=redis", nil)
	req4.Header.Set("Authorization", "Bearer "+tok)
	rec4 := httptest.NewRecorder()
	h.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusOK || !strings.Contains(rec4.Body.String(), sub.SBOMID) {
		t.Errorf("/v1/images/sboms?repo=redis should include %s, got %s", sub.SBOMID, rec4.Body.String())
	}
}

func TestRead_TenantIsolation(t *testing.T) {
	srv, st := testServer(t)
	_, tokA := seedTenantToken(t, st)
	_, tokB := seedTenantToken(t, st)
	h := srv.Handler()

	raw, err := os.ReadFile("../sbom/testdata/redis.syft.cdx.json")
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	body, _ := json.Marshal(map[string]string{"sbom": base64.StdEncoding.EncodeToString(raw)})

	// Tenant A submits.
	req := httptest.NewRequest(http.MethodPost, "/v1/sboms", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+tokA)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var sub struct {
		SBOMID string `json:"sbom_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &sub)

	// Tenant B cannot read A's SBOM → 404.
	req2 := httptest.NewRequest(http.MethodGet, "/v1/sboms/"+sub.SBOMID+"/findings", nil)
	req2.Header.Set("Authorization", "Bearer "+tokB)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Errorf("cross-tenant read = %d, want 404", rec2.Code)
	}
}

// TestSBOMLifecycle covers GET /v1/sboms/{id}, DELETE (archive), and that an
// archived SBOM drops from the images list.
func TestSBOMLifecycle(t *testing.T) {
	srv, st := testServer(t)
	_, tok := seedTenantToken(t, st)
	h := srv.Handler()

	raw, err := os.ReadFile("../sbom/testdata/redis.syft.cdx.json")
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	body, _ := json.Marshal(map[string]string{"sbom": base64.StdEncoding.EncodeToString(raw)})
	req := httptest.NewRequest(http.MethodPost, "/v1/sboms", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var sub struct {
		SBOMID string `json:"sbom_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &sub)

	do := func(method, path string) *httptest.ResponseRecorder {
		rq := httptest.NewRequest(method, path, nil)
		rq.Header.Set("Authorization", "Bearer "+tok)
		rc := httptest.NewRecorder()
		h.ServeHTTP(rc, rq)
		return rc
	}

	// GET metadata.
	if rc := do(http.MethodGet, "/v1/sboms/"+sub.SBOMID); rc.Code != http.StatusOK ||
		!strings.Contains(rc.Body.String(), `"digest"`) {
		t.Errorf("GET sbom = %d: %s", rc.Code, rc.Body.String())
	}
	// GET unknown → 404.
	if rc := do(http.MethodGet, "/v1/sboms/nope"); rc.Code != http.StatusNotFound {
		t.Errorf("GET unknown sbom = %d, want 404", rc.Code)
	}
	// Archive → 204.
	if rc := do(http.MethodDelete, "/v1/sboms/"+sub.SBOMID); rc.Code != http.StatusNoContent {
		t.Errorf("DELETE sbom = %d, want 204", rc.Code)
	}
	// Archive again → still 204 (idempotent).
	if rc := do(http.MethodDelete, "/v1/sboms/"+sub.SBOMID); rc.Code != http.StatusNoContent {
		t.Errorf("DELETE sbom (repeat) = %d, want 204", rc.Code)
	}
	// Archived SBOM no longer in images.
	if rc := do(http.MethodGet, "/v1/images"); strings.Contains(rc.Body.String(), sub.SBOMID) {
		t.Errorf("archived sbom should not appear in /v1/images")
	}
	// DELETE unknown → 404.
	if rc := do(http.MethodDelete, "/v1/sboms/nope"); rc.Code != http.StatusNotFound {
		t.Errorf("DELETE unknown sbom = %d, want 404", rc.Code)
	}
}

// TestFailures covers GET /v1/sboms/{id}/failures: a recorded scan failure is
// returned to the owner, the /v1/images rollup reflects it, and another tenant
// gets 404. This is the observability path for a scanner that silently returns
// nothing (e.g. Trivy on an EOL distro).
func TestFailures(t *testing.T) {
	srv, st := testServer(t)
	_, tok := seedTenantToken(t, st)
	_, tokB := seedTenantToken(t, st)
	h := srv.Handler()
	ctx := context.Background()

	raw, err := os.ReadFile("../sbom/testdata/redis.syft.cdx.json")
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	body, _ := json.Marshal(map[string]string{"sbom": base64.StdEncoding.EncodeToString(raw)})
	req := httptest.NewRequest(http.MethodPost, "/v1/sboms", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var sub struct {
		SBOMID string `json:"sbom_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &sub)

	// Record a zero-findings failure the way the scan job would.
	st.RecordScanFailure(ctx, sub.SBOMID, "trivy", "zero-findings",
		errors.New("0 findings on sbom with 42 packages"))

	do := func(tokenStr, method, path string) *httptest.ResponseRecorder {
		rq := httptest.NewRequest(method, path, nil)
		rq.Header.Set("Authorization", "Bearer "+tokenStr)
		rc := httptest.NewRecorder()
		h.ServeHTTP(rc, rq)
		return rc
	}

	// Owner sees the failure with scanner + stage.
	rc := do(tok, http.MethodGet, "/v1/sboms/"+sub.SBOMID+"/failures")
	if rc.Code != http.StatusOK ||
		!strings.Contains(rc.Body.String(), `"trivy"`) ||
		!strings.Contains(rc.Body.String(), `"zero-findings"`) {
		t.Errorf("GET failures = %d: %s", rc.Code, rc.Body.String())
	}
	// The images rollup surfaces a non-zero failure count.
	if rc := do(tok, http.MethodGet, "/v1/images"); !strings.Contains(rc.Body.String(), `"failures":1`) {
		t.Errorf("images should report failures:1, got: %s", rc.Body.String())
	}
	// Cross-tenant read → 404 (owner-scoped).
	if rc := do(tokB, http.MethodGet, "/v1/sboms/"+sub.SBOMID+"/failures"); rc.Code != http.StatusNotFound {
		t.Errorf("cross-tenant failures = %d, want 404", rc.Code)
	}
	// Unknown SBOM → 404.
	if rc := do(tok, http.MethodGet, "/v1/sboms/nope/failures"); rc.Code != http.StatusNotFound {
		t.Errorf("unknown sbom failures = %d, want 404", rc.Code)
	}
}

// TestIngest_GzipAndBomb checks gzip SBOM acceptance and decompression-bomb
// rejection.
func TestIngest_GzipAndBomb(t *testing.T) {
	srv, st := testServer(t)
	_, tok := seedTenantToken(t, st)
	h := srv.Handler()

	raw, err := os.ReadFile("../sbom/testdata/redis.syft.cdx.json")
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}

	submit := func(payload []byte) int {
		body, _ := json.Marshal(map[string]string{"sbom": base64.StdEncoding.EncodeToString(payload)})
		rq := httptest.NewRequest(http.MethodPost, "/v1/sboms", strings.NewReader(string(body)))
		rq.Header.Set("Authorization", "Bearer "+tok)
		rc := httptest.NewRecorder()
		h.ServeHTTP(rc, rq)
		return rc.Code
	}

	// A gzip-compressed valid SBOM is accepted.
	var gzbuf bytes.Buffer
	zw := gzip.NewWriter(&gzbuf)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	if code := submit(gzbuf.Bytes()); code != http.StatusAccepted {
		t.Errorf("gzip sbom = %d, want 202", code)
	}

	// A decompression bomb (tiny gzip, huge output) is rejected, not OOM.
	var bomb bytes.Buffer
	bw := gzip.NewWriter(&bomb)
	huge := bytes.Repeat([]byte("A"), (20<<20)+1024) // > maxSBOMBytes
	_, _ = bw.Write(huge)
	_ = bw.Close()
	if code := submit(bomb.Bytes()); code != http.StatusBadRequest && code != http.StatusRequestEntityTooLarge {
		t.Errorf("decompression bomb = %d, want 400/413", code)
	}
}

// TestFindings_SeverityThreshold seeds findings at each level and checks that
// ?min_severity filters correctly, that unknown is always included, and that an
// invalid value is rejected.
func TestFindings_SeverityThreshold(t *testing.T) {
	srv, st := testServer(t)
	tenantID, tok := seedTenantToken(t, st)
	h := srv.Handler()
	ctx := context.Background()

	// Seed an SBOM row + one finding per severity directly.
	sbomID := "thr-" + tenantID
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_sbom (id, tenant_id, image_ref, digest, format, object_path)
		VALUES ($1,$2,'img','sha256:x','cyclonedx','gs://x')`, sbomID, tenantID); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}
	for _, sev := range []string{"critical", "high", "medium", "low", "negligible", "unknown"} {
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_finding (sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
			VALUES ($1,'grype',$2,$3,'pkg','1.0',$4,1.0,false)`,
			sbomID, "f-"+sev, "CVE-"+sev, sev); err != nil {
			t.Fatalf("seed finding %s: %v", sev, err)
		}
	}

	count := func(query string) int {
		req := httptest.NewRequest(http.MethodGet, "/v1/sboms/"+sbomID+"/findings"+query, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("findings%s: status %d (%s)", query, rec.Code, rec.Body.String())
		}
		var body struct {
			Findings []struct {
				Severity string `json:"severity"`
			} `json:"findings"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return len(body.Findings)
	}

	// Default (medium): critical, high, medium, + unknown = 4.
	if n := count(""); n != 4 {
		t.Errorf("default threshold: %d findings, want 4 (crit/high/med/unknown)", n)
	}
	// critical: critical + unknown = 2.
	if n := count("?min_severity=critical"); n != 2 {
		t.Errorf("critical threshold: %d findings, want 2 (crit/unknown)", n)
	}
	// negligible: everything = 6.
	if n := count("?min_severity=negligible"); n != 6 {
		t.Errorf("negligible threshold: %d findings, want 6 (all)", n)
	}
	// invalid → 400.
	req := httptest.NewRequest(http.MethodGet, "/v1/sboms/"+sbomID+"/findings?min_severity=nope", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid min_severity: status %d, want 400", rec.Code)
	}
}

// TestVEX_SubmitAndSuppress covers the full VEX round trip over HTTP: post an
// OpenVEX doc, confirm it suppresses the matched finding by default and that
// ?suppressed=true reveals it, and that an invalid doc is rejected.
func TestVEX_SubmitAndSuppress(t *testing.T) {
	srv, st := testServer(t)
	tenantID, tok := seedTenantToken(t, st)
	h := srv.Handler()
	ctx := context.Background()

	digest := "sha256:" + hex.EncodeToString(mustRand(t, 32))
	sbomID := "vex-" + tenantID
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_sbom (id, tenant_id, image_ref, repository, digest, format, object_path)
		VALUES ($1,$2,'reg/app','reg/app',$3,'cyclonedx','gs://x')`, sbomID, tenantID, digest); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}
	for _, cve := range []string{"CVE-2025-1", "CVE-2025-2"} {
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_finding (sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
			VALUES ($1,'grype',$2,$3,'p','1','high',7.0,false)`, sbomID, cve+"/p/1", cve); err != nil {
			t.Fatalf("seed finding: %v", err)
		}
	}

	do := func(method, path, body string) *httptest.ResponseRecorder {
		rq := httptest.NewRequest(method, path, strings.NewReader(body))
		rq.Header.Set("Authorization", "Bearer "+tok)
		rc := httptest.NewRecorder()
		h.ServeHTTP(rc, rq)
		return rc
	}
	countFindings := func(query string) int {
		rc := do(http.MethodGet, "/v1/sboms/"+sbomID+"/findings?min_severity=negligible"+query, "")
		var body struct {
			Findings []json.RawMessage `json:"findings"`
		}
		_ = json.Unmarshal(rc.Body.Bytes(), &body)
		return len(body.Findings)
	}

	if countFindings("") != 2 {
		t.Fatalf("pre-VEX findings = %d, want 2", countFindings(""))
	}

	// Post a valid VEX suppressing CVE-2025-1.
	doc := `{"@context":"https://openvex.dev/ns","author":"sec@x","statements":[
		{"vulnerability":"CVE-2025-1","products":[{"@id":"` + digest + `"}],
		 "status":"not_affected","justification":"vulnerable_code_not_in_execute_path"}]}`
	rc := do(http.MethodPost, "/v1/vex", doc)
	if rc.Code != http.StatusAccepted || !strings.Contains(rc.Body.String(), `"matched":1`) {
		t.Fatalf("POST /v1/vex = %d: %s", rc.Code, rc.Body.String())
	}

	if got := countFindings(""); got != 1 {
		t.Errorf("post-VEX default findings = %d, want 1 (one suppressed)", got)
	}
	if got := countFindings("&suppressed=true"); got != 2 {
		t.Errorf("suppressed=true findings = %d, want 2", got)
	}

	// Invalid VEX (not_affected without justification) → 422.
	bad := `{"statements":[{"vulnerability":"CVE-2025-2","products":[{"@id":"` + digest + `"}],"status":"not_affected"}]}`
	if rc := do(http.MethodPost, "/v1/vex", bad); rc.Code != http.StatusUnprocessableEntity {
		t.Errorf("invalid VEX: status %d, want 422", rc.Code)
	}
}

// TestVEX_RealAICRFile validates the real NVIDIA AICR OpenVEX document (fixture)
// end-to-end: it's digest-less (repository-scoped), so it must suppress the
// matching CVE on a tracked aicr image across versions.
func TestVEX_RealAICRFile(t *testing.T) {
	raw, err := os.ReadFile("testdata/aicr.openvex.json")
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	srv, st := testServer(t)
	tenantID, tok := seedTenantToken(t, st)
	h := srv.Handler()
	ctx := context.Background()

	// A tracked ghcr.io/nvidia/aicr image with CVE-2026-45447 (which the AICR VEX
	// marks not_affected for pkg:oci/aicr).
	digest := "sha256:" + hex.EncodeToString(mustRand(t, 32))
	sbomID := "aicr-" + tenantID
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_sbom (id, tenant_id, image_ref, repository, digest, format, object_path)
		VALUES ($1,$2,'ghcr.io/nvidia/aicr','ghcr.io/nvidia/aicr',$3,'cyclonedx','gs://x')`,
		sbomID, tenantID, digest); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_finding (sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
		VALUES ($1,'grype','CVE-2026-45447/p/1','CVE-2026-45447','p','1','high',7.0,false)`, sbomID); err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	do := func(method, path string, body []byte) *httptest.ResponseRecorder {
		rq := httptest.NewRequest(method, path, bytes.NewReader(body))
		rq.Header.Set("Authorization", "Bearer "+tok)
		rc := httptest.NewRecorder()
		h.ServeHTTP(rc, rq)
		return rc
	}
	findings := func(query string) int {
		rc := do(http.MethodGet, "/v1/sboms/"+sbomID+"/findings?min_severity=negligible"+query, nil)
		var b struct {
			Findings []json.RawMessage `json:"findings"`
		}
		_ = json.Unmarshal(rc.Body.Bytes(), &b)
		return len(b.Findings)
	}

	if findings("") != 1 {
		t.Fatalf("pre-VEX findings = %d, want 1", findings(""))
	}
	// Submit the real AICR document.
	rc := do(http.MethodPost, "/v1/vex", raw)
	if rc.Code != http.StatusAccepted {
		t.Fatalf("POST real AICR VEX = %d: %s", rc.Code, rc.Body.String())
	}
	// It parses all 56 statements and matches the one for our aicr image.
	if !strings.Contains(rc.Body.String(), `"matched":1`) {
		t.Errorf("AICR VEX should match 1 finding, got: %s", rc.Body.String())
	}
	// The finding is now suppressed (repository-scoped, digest-less statement).
	if findings("") != 0 {
		t.Errorf("post-VEX findings = %d, want 0 (repo-scoped suppression)", findings(""))
	}
	if findings("&suppressed=true") != 1 {
		t.Errorf("suppressed=true findings = %d, want 1", findings("&suppressed=true"))
	}
}

func mustRand(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestVEX_UIUpload covers the browser VEX upload on the CVEs tab: a multipart
// file post is parsed + persisted and suppresses/annotates the matched CVE.
func TestVEX_UIUpload(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	h := srv.Handler()
	ctx := context.Background()
	cookie := seedSession(t, st, tenantID)

	digest := "sha256:" + hex.EncodeToString(mustRand(t, 32))
	sbomID := "vexui-" + tenantID
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_sbom (id, tenant_id, image_ref, repository, digest, format, object_path)
		VALUES ($1,$2,'reg/app','reg/app',$3,'cyclonedx','gs://x')`, sbomID, tenantID, digest); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_finding (sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
		VALUES ($1,'grype','CVE-UI-1/p/1','CVE-UI-1','p','1','high',7.0,false)`, sbomID); err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	// Build a multipart upload with the VEX doc.
	doc := `{"@context":"https://openvex.dev/ns","author":"a","statements":[
		{"vulnerability":"CVE-UI-1","products":[{"@id":"` + digest + `"}],
		 "status":"not_affected","justification":"component_not_present"}]}`
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("vex", "vex.json")
	_, _ = fw.Write([]byte(doc))
	_ = mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/vex/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("upload = %d, want 303: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "uploaded=") {
		t.Errorf("redirect should carry an upload summary, got %q", loc)
	}

	// The CVE now shows a not_affected VEX status in the fleet list.
	cves, _, err := st.FleetCVEs(ctx, tenantID, "negligible", postgres.FleetCVEFilter{}, "", "", "", 50)
	if err != nil {
		t.Fatalf("fleet cves: %v", err)
	}
	var found bool
	for _, c := range cves {
		if c.CVE == "CVE-UI-1" {
			found = true
			if c.VEXStatus != "not_affected" || !c.Suppressed {
				t.Errorf("uploaded VEX not reflected: %+v", c)
			}
		}
	}
	if !found {
		t.Errorf("CVE-UI-1 should still appear (VEX'd shown, not dropped)")
	}
}

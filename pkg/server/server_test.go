package server_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/gcs"
	"github.com/thingzio/devradar/pkg/server"
	"github.com/thingzio/devradar/pkg/tenant"
)

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

	// List images includes it.
	req3 := httptest.NewRequest(http.MethodGet, "/v1/images", nil)
	req3.Header.Set("Authorization", "Bearer "+tok)
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK || !strings.Contains(rec3.Body.String(), sub.SBOMID) {
		t.Errorf("images should include %s, got %s", sub.SBOMID, rec3.Body.String())
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

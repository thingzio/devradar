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
	var gh int64
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	for _, c := range b {
		gh = gh<<8 | int64(c)
	}
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (github_id, username) VALUES ($1,$2) RETURNING id`,
		gh, "u"+hex.EncodeToString(b)).Scan(&tenantID); err != nil {
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

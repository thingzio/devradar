package server_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/gcs"
	"github.com/thingzio/devradar/pkg/server"
)

// flakyBlob is a BlobStore whose Put fails until failN calls have been made,
// then succeeds — modeling a transient object-storage outage so we can assert
// the pending→active lifecycle self-heals on retry.
type flakyBlob struct {
	inner  gcs.Store
	fail   bool
	failN  int
	calls  int
	putErr error
}

func (b *flakyBlob) Put(ctx context.Context, objectPath string, data []byte) error {
	b.calls++
	if b.fail && b.calls <= b.failN {
		return b.putErr
	}
	return b.inner.Put(ctx, objectPath, data)
}

// sbomStatus reads the raw status column for one SBOM id (empty if the row is
// absent — e.g. a cleaned-up pending row).
func sbomStatus(t *testing.T, st *postgres.Store, id string) string {
	t.Helper()
	var status string
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT status FROM devradar_sbom WHERE id=$1`, id).Scan(&status); err != nil {
		return "" // no row (e.g. a cleaned-up pending row)
	}
	return status
}

// serverWithBlob builds a Server with a caller-supplied blob store so a test can
// inject storage failures. Mirrors testServer's DB skip behavior.
func serverWithBlob(t *testing.T, blobs server.BlobStore) (*server.Server, *postgres.Store) {
	t.Helper()
	st := testPostgresStore(t)
	return server.New(st, blobs, nil, nil, server.Options{Version: "test"}), st
}

func submitBody(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../sbom/testdata/redis.syft.cdx.json")
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	body, _ := json.Marshal(map[string]string{"sbom": base64.StdEncoding.EncodeToString(raw)})
	return string(body)
}

// TestIngest_LifecycleActivatesOnSuccess: a normal submission stores bytes and
// ends with the row 'active' (visible to scan + read).
func TestIngest_LifecycleActivatesOnSuccess(t *testing.T) {
	blob := &flakyBlob{inner: gcs.LocalStore{Dir: t.TempDir()}}
	srv, st := serverWithBlob(t, blob)
	_, tok := seedTenantToken(t, st)
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodPost, "/v1/sboms", strings.NewReader(submitBody(t)))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("submit = %d, want 202: %s", rec.Code, rec.Body.String())
	}
	var sub struct {
		SBOMID string `json:"sbom_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &sub)

	if got := sbomStatus(t, st, sub.SBOMID); got != "active" {
		t.Errorf("status = %q, want active", got)
	}
	if blob.calls != 1 {
		t.Errorf("Put calls = %d, want 1", blob.calls)
	}
}

// TestIngest_LifecycleBlobFailureNoActiveRow: if storing the bytes fails, the
// submission returns 500 and leaves NO active row — the pending row is cleaned
// up, so nothing unscannable is stranded.
func TestIngest_LifecycleBlobFailureNoActiveRow(t *testing.T) {
	blob := &flakyBlob{inner: gcs.LocalStore{Dir: t.TempDir()}, fail: true, failN: 1000, putErr: errors.New("gcs down")}
	srv, st := serverWithBlob(t, blob)
	tenantID, tok := seedTenantToken(t, st)
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodPost, "/v1/sboms", strings.NewReader(submitBody(t)))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("submit with failing blob = %d, want 500", rec.Code)
	}

	// No row of any status remains for this tenant — the pending row was cleaned
	// up, so nothing unscannable is stranded.
	var rows int
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM devradar_sbom WHERE tenant_id=$1`, tenantID).Scan(&rows); err != nil {
		t.Fatalf("count tenant rows: %v", err)
	}
	if rows != 0 {
		t.Errorf("expected no stranded row after blob failure, found %d", rows)
	}
}

// TestIngest_LifecycleSelfHealsOnRetry: a transient blob failure leaves nothing
// active; a retry (blob now healthy) succeeds and produces exactly one active
// row. Verifies the self-heal path (pending row re-driven on resubmit).
func TestIngest_LifecycleSelfHealsOnRetry(t *testing.T) {
	// First Put fails, subsequent succeed.
	blob := &flakyBlob{inner: gcs.LocalStore{Dir: t.TempDir()}, fail: true, failN: 1, putErr: errors.New("transient")}
	srv, st := serverWithBlob(t, blob)
	_, tok := seedTenantToken(t, st)
	h := srv.Handler()
	body := submitBody(t)

	do := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/sboms", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rc := do(); rc.Code != http.StatusInternalServerError {
		t.Fatalf("first submit = %d, want 500", rc.Code)
	}
	rc := do()
	if rc.Code != http.StatusAccepted {
		t.Fatalf("retry submit = %d, want 202: %s", rc.Code, rc.Body.String())
	}
	var sub struct {
		SBOMID string `json:"sbom_id"`
	}
	_ = json.Unmarshal(rc.Body.Bytes(), &sub)
	if got := sbomStatus(t, st, sub.SBOMID); got != "active" {
		t.Errorf("after retry status = %q, want active", got)
	}
	// Exactly one row for this SBOM id.
	var rows int
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM devradar_sbom WHERE id=$1`, sub.SBOMID).Scan(&rows); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rows != 1 {
		t.Errorf("want exactly 1 row, got %d", rows)
	}
}

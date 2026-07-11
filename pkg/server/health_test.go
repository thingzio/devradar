package server_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHealthAndReady verifies liveness is a cheap static 200 and readiness
// returns 200 when Postgres is reachable (the DB-backed startup probe target).
func TestHealthAndReady(t *testing.T) {
	srv, _ := testServer(t) // skips if no DB
	h := srv.Handler()

	for _, path := range []string{"/health", "/ready"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200 (%s)", path, rec.Code, rec.Body.String())
		}
	}
}

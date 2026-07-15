package server

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/lib/pq"
)

func TestInvitationRateLimitFailsClosedOnDatabaseError(t *testing.T) {
	db, err := sql.Open("postgres", "postgres://unused")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := allowInvitationSend(context.Background(), db, "account", "recipient@example.com"); err == nil {
		t.Fatal("closed limiter database allowed an invitation send")
	}
}

func TestInvitationSecurityWrapperRedactsApplicationPathAndDisablesCaching(t *testing.T) {
	var gotPath string
	handler := secureInvitationPath(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet,
		"/account-invitations/00000000-0000-0000-0000-000000000001", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if gotPath != "/account-invitations/{id}" {
		t.Fatalf("application path = %q", gotPath)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("security headers = %v", rec.Header())
	}
}

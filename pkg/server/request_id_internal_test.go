package server

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/thingzio/devradar/pkg/middleware"
)

func TestRecoverPanicsLogsRequestID(t *testing.T) {
	var logs bytes.Buffer
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(original) })

	h := middleware.RequestID(recoverPanics(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panic", nil))
	requestID := rec.Header().Get("X-Request-ID")
	if requestID == "" {
		t.Fatal("panic response request ID is empty")
	}
	if !strings.Contains(logs.String(), `"request_id":"`+requestID+`"`) {
		t.Fatalf("panic log does not contain request ID %q: %s", requestID, logs.String())
	}
}

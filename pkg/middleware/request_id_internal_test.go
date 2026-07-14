package middleware

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestRequestIDEntropyFailureUsesUniqueFallbackAndContinues(t *testing.T) {
	original := readRequestIDEntropy
	readRequestIDEntropy = func([]byte) (int, error) {
		return 0, errors.New("entropy unavailable")
	}
	t.Cleanup(func() { readRequestIDEntropy = original })
	var logs bytes.Buffer
	originalLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(originalLogger) })

	var contextIDs []string
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextIDs = append(contextIDs, RequestIDFromContext(r.Context()))
		http.Error(w, "inner failure", http.StatusInternalServerError)
	}))
	responseIDs := make([]string, 0, 2)
	for range 2 {
		req := httptest.NewRequest(http.MethodGet, "/failure", nil)
		req.Header.Set(requestIDHeader, "spoofed")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want inner handler status %d", rec.Code, http.StatusInternalServerError)
		}
		responseIDs = append(responseIDs, rec.Header().Get(requestIDHeader))
	}

	pattern := regexp.MustCompile(`^[0-9a-f]{32}$`)
	for i := range responseIDs {
		if !pattern.MatchString(responseIDs[i]) || responseIDs[i] == "spoofed" || responseIDs[i] != contextIDs[i] {
			t.Fatalf("request %d response/context IDs = %q/%q", i, responseIDs[i], contextIDs[i])
		}
	}
	if responseIDs[0] == responseIDs[1] {
		t.Fatalf("fallback request IDs are duplicates: %q", responseIDs[0])
	}
	for _, id := range responseIDs {
		if !strings.Contains(logs.String(), `"request_id":"`+id+`"`) {
			t.Fatalf("entropy failure log missing fallback request ID %q: %s", id, logs.String())
		}
	}
}

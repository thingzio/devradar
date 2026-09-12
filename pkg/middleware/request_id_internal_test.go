// Copyright 2026 Thingz LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

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

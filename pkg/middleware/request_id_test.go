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

package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/thingzio/devradar/pkg/middleware"
)

func TestRequestIDIgnoresSpoofedHeaderAndSetsContextAndResponse(t *testing.T) {
	const spoofed = "client-controlled-request-id"
	var contextID string
	h := middleware.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextID = middleware.RequestIDFromContext(r.Context())
		http.Error(w, "expected error", http.StatusTeapot)
	}))
	req := httptest.NewRequest(http.MethodGet, "/error", nil)
	req.Header.Set("X-Request-ID", spoofed)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	responseID := rec.Header().Get("X-Request-ID")
	if responseID == spoofed || contextID == spoofed {
		t.Fatal("request ID middleware trusted the client-supplied primary ID")
	}
	if responseID != contextID {
		t.Fatalf("response/context request IDs = %q/%q, want equal", responseID, contextID)
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(responseID) {
		t.Fatalf("request ID = %q, want random 128-bit lowercase hex", responseID)
	}
	if rec.Code != http.StatusTeapot {
		t.Fatalf("error status = %d, want %d", rec.Code, http.StatusTeapot)
	}
}

func TestRequestIDIsUniquePerRequest(t *testing.T) {
	h := middleware.RequestID(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	seen := make(map[string]struct{}, 128)
	for i := 0; i < 128; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		id := rec.Header().Get("X-Request-ID")
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("duplicate request ID %q at request %d", id, i)
		}
		seen[id] = struct{}{}
	}
}

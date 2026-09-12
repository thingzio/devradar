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

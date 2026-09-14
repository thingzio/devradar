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

// TestPublicPagesReachableSignedOut guards the footer contract: every link the
// footer renders on the landing page must resolve without a session. /help and
// /tos join this list once Task 12 and Task 13 create them.
func TestPublicPagesReachableSignedOut(t *testing.T) {
	srv, _ := testServer(t)

	for _, path := range []string{"/docs", "/api", "/help", "/tos"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("GET %s signed out = %d, want 200", path, rec.Code)
			}
		})
	}
}

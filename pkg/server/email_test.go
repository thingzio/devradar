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
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/thingzio/devradar/pkg/gcs"
	drnet "github.com/thingzio/devradar/pkg/net"
	"github.com/thingzio/devradar/pkg/server"
)

type recordingSender struct {
	mu      sync.Mutex
	message drnet.Message
}

func (s *recordingSender) Send(_ context.Context, message drnet.Message) (drnet.Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.message = message
	return drnet.Receipt{ID: "fake-provider-id"}, nil
}

func TestMagicLinkUsesStoredTokenHashAsStableIdempotencyKey(t *testing.T) {
	st := testPostgresStore(t)
	sender := &recordingSender{}
	srv := server.New(st, gcs.LocalStore{Dir: t.TempDir()}, sender, nil, nil, server.Options{Version: "test"})
	email := "idempotent-" + mustRandomHex(t, 6) + "@example.com"
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader("email="+email))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}

	var tokenHash string
	if err := st.DB().QueryRow(`SELECT id FROM devradar_login_token WHERE email=$1 ORDER BY created_at DESC LIMIT 1`, email).
		Scan(&tokenHash); err != nil {
		t.Fatalf("read login token hash: %v", err)
	}
	sender.mu.Lock()
	message := sender.message
	sender.mu.Unlock()
	if message.To != email || message.IdempotencyKey != "magic-link/"+tokenHash {
		t.Fatalf("message recipient=%q idempotency=%q, want %q", message.To, message.IdempotencyKey, "magic-link/"+tokenHash)
	}
	if strings.Contains(message.IdempotencyKey, "token=") || message.Subject == "" || message.HTML == "" || message.Text == "" {
		t.Fatalf("unsafe/incomplete message = %#v", message)
	}
}

func mustRandomHex(t *testing.T, size int) string {
	t.Helper()
	return hex.EncodeToString(mustRand(t, size))
}

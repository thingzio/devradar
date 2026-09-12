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

package postgres_test

import (
	"context"
	"testing"
)

// TestPurgeExpiredAuth verifies the janitor deletes expired login tokens and
// sessions while leaving live ones intact.
func TestPurgeExpiredAuth(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	var tenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"purge-"+randID(t)[:8]+"@example.com").Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	// Unique per run so the live login token doesn't accumulate across reruns
	// (the login_token table has no tenant FK to scope by).
	liveEmail := "purge-live-" + randID(t)[:8] + "@example.com"

	// Two sessions: one already expired, one live.
	expiredSessionID := randID(t)
	expiredFlashSessionID := randID(t)
	liveFlashSessionID := randID(t)
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO devradar_session (id, tenant_id, expires_at) VALUES
		 ($1, $2, now() - interval '1 hour'),
		 ($3, $2, now() + interval '1 hour'),
		 ($4, $2, now() + interval '1 hour')`,
		expiredSessionID, tenantID, expiredFlashSessionID, liveFlashSessionID); err != nil {
		t.Fatalf("seed sessions: %v", err)
	}
	// Two login tokens: one expired, one live.
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO devradar_login_token (id, email, expires_at) VALUES
		 ($1, $2, now() - interval '1 hour'),
		 ($3, $2, now() + interval '1 hour')`,
		randID(t), liveEmail, randID(t)); err != nil {
		t.Fatalf("seed login tokens: %v", err)
	}
	// Token-flash rows are keyed by tenant (PK), so use two tenants: this one has
	// an EXPIRED flash (must be purged — a lingering plaintext token), a second has
	// a LIVE flash (must survive).
	var liveFlashTenant string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"flash-live-"+randID(t)[:8]+"@example.com").Scan(&liveFlashTenant); err != nil {
		t.Fatalf("seed flash tenant: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO devradar_token_flash (tenant_id, value, expires_at) VALUES
		 ($1, 'dr_expired_plaintext', now() - interval '1 hour'),
		 ($2, 'dr_live_plaintext',    now() + interval '1 hour')`,
		tenantID, liveFlashTenant); err != nil {
		t.Fatalf("seed token flash: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_session_token_flash (session_id,account_id,value,expires_at) VALUES
		 ($1,$2,'enc:expired',now()-interval '1 hour'),
		 ($3,$2,'enc:live',now()+interval '1 hour')`,
		expiredFlashSessionID, tenantID, liveFlashSessionID); err != nil {
		t.Fatalf("seed session token flash: %v", err)
	}

	if err := st.PurgeExpiredAuth(ctx); err != nil {
		t.Fatalf("purge: %v", err)
	}

	// Only the live rows survive.
	var sessions, tokens int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM devradar_session WHERE tenant_id=$1`, tenantID).Scan(&sessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessions != 2 {
		t.Errorf("live sessions after purge = %d, want 2", sessions)
	}
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM devradar_login_token WHERE email=$1`, liveEmail).Scan(&tokens); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if tokens != 1 {
		t.Errorf("live login tokens after purge = %d, want 1", tokens)
	}
	// The expired flash (plaintext token) is gone; the live one survives.
	var expiredFlash, liveFlash int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM devradar_token_flash WHERE tenant_id=$1`, tenantID).Scan(&expiredFlash); err != nil {
		t.Fatalf("count expired flash: %v", err)
	}
	if expiredFlash != 0 {
		t.Errorf("expired token-flash row must be purged, got %d", expiredFlash)
	}
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM devradar_token_flash WHERE tenant_id=$1`, liveFlashTenant).Scan(&liveFlash); err != nil {
		t.Fatalf("count live flash: %v", err)
	}
	if liveFlash != 1 {
		t.Errorf("live token-flash row must survive, got %d", liveFlash)
	}
	var sessionFlashes int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT count(*) FROM devradar_session_token_flash WHERE account_id=$1`, tenantID).
		Scan(&sessionFlashes); err != nil {
		t.Fatalf("count session token flashes: %v", err)
	}
	if sessionFlashes != 1 {
		t.Errorf("live session token flashes after purge = %d, want 1", sessionFlashes)
	}
}

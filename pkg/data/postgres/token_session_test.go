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
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/authn"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

func TestAPITokenCreateLinearizesWithSessionSelection(t *testing.T) {
	t.Run("selection wins", func(t *testing.T) {
		st := isolatedAdminProductHealthStore(t)
		ctx := context.Background()
		accountID, adminID := seedAuditAccount(t, st)
		otherAccountID := seedAccountMembership(t, st, adminID, string(account.RoleAdmin))
		session := createTokenSession(t, st, adminID, accountID, time.Hour)
		holder, holderPID := selectSessionInOpenTransaction(t, st, session, otherAccountID)

		result := make(chan error, 1)
		requestID := randID(t)
		go func() {
			_, err := st.CreateAPIToken(ctx, accountID, adminID, authn.HashToken(session),
				"selection-wins", 0, 10, requestID, bytes.Repeat([]byte{0x11}, 32))
			result <- err
		}()
		if !waitForPostgresBlockers(ctx, st.DB(), holderPID, 1, 5*time.Second) {
			t.Fatal("token create did not wait for the session selection")
		}
		if err := holder.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := <-result; !errors.Is(err, postgres.ErrForbidden) {
			t.Fatalf("create after selection = %v, want ErrForbidden", err)
		}
		assertSessionAccounts(t, st, session, &otherAccountID, &otherAccountID)
		assertTokenMutationCounts(t, st, accountID, 0, 0, 0)
	})

	t.Run("create wins", func(t *testing.T) {
		st := isolatedAdminProductHealthStore(t)
		ctx := context.Background()
		accountID, adminID := seedAuditAccount(t, st)
		otherAccountID := seedAccountMembership(t, st, adminID, string(account.RoleAdmin))
		session := createTokenSession(t, st, adminID, accountID, time.Hour)
		key := bytes.Repeat([]byte{0x12}, 32)
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_session_token_flash (session_id,account_id,value,expires_at)
			VALUES ($1,$2,'enc:placeholder',now()+interval '2 minutes')`,
			authn.HashToken(session), accountID); err != nil {
			t.Fatal(err)
		}
		barrier := installFlashTriggerBarrier(t, st, "UPDATE")

		createResult := make(chan error, 1)
		requestID := randID(t)
		go func() {
			_, err := st.CreateAPIToken(ctx, accountID, adminID, authn.HashToken(session),
				"create-wins", 0, 10, requestID, key)
			createResult <- err
		}()
		createPID := waitForBlockedPID(t, st.DB(), barrier.holderPID)
		switchResult := make(chan error, 1)
		go func() { switchResult <- st.SelectSessionAccount(ctx, session, adminID, otherAccountID) }()
		if !waitForPostgresBlockers(ctx, st.DB(), createPID, 1, 5*time.Second) {
			t.Fatal("session selection did not wait for token create")
		}
		barrier.release(t)
		if err := <-createResult; err != nil {
			t.Fatalf("create winner: %v", err)
		}
		if err := <-switchResult; err != nil {
			t.Fatalf("select after create: %v", err)
		}
		assertSessionAccounts(t, st, session, &otherAccountID, &otherAccountID)
		assertTokenMutationCounts(t, st, accountID, 1, 1, 1)
		if raw, err := st.ConsumeTokenFlash(ctx, authn.HashToken(session), accountID, key); err != nil || raw != "" {
			t.Fatalf("old-account flash after selection = %q, %v", raw, err)
		}
	})
}

func TestTokenFlashConsumeLinearizesWithSessionSelection(t *testing.T) {
	t.Run("selection wins", func(t *testing.T) {
		st := isolatedAdminProductHealthStore(t)
		ctx := context.Background()
		accountID, adminID := seedAuditAccount(t, st)
		otherAccountID := seedAccountMembership(t, st, adminID, string(account.RoleAdmin))
		session := createTokenSession(t, st, adminID, accountID, time.Hour)
		key := bytes.Repeat([]byte{0x21}, 32)
		if _, err := st.CreateAPIToken(ctx, accountID, adminID, authn.HashToken(session),
			"consume-selection-wins", 0, 10, randID(t), key); err != nil {
			t.Fatal(err)
		}
		holder, holderPID := selectSessionInOpenTransaction(t, st, session, otherAccountID)
		type consumeResult struct {
			raw string
			err error
		}
		result := make(chan consumeResult, 1)
		go func() {
			raw, err := st.ConsumeTokenFlash(ctx, authn.HashToken(session), accountID, key)
			result <- consumeResult{raw: raw, err: err}
		}()
		if !waitForPostgresBlockers(ctx, st.DB(), holderPID, 1, 5*time.Second) {
			t.Fatal("flash consume did not wait for the session selection")
		}
		if err := holder.Commit(); err != nil {
			t.Fatal(err)
		}
		got := <-result
		if got.err != nil || got.raw != "" {
			t.Fatalf("consume after selection = %q, %v, want empty", got.raw, got.err)
		}
		assertSessionAccounts(t, st, session, &otherAccountID, &otherAccountID)
		assertTokenMutationCounts(t, st, accountID, 1, 1, 1)
	})

	t.Run("consume wins", func(t *testing.T) {
		st := isolatedAdminProductHealthStore(t)
		ctx := context.Background()
		accountID, adminID := seedAuditAccount(t, st)
		otherAccountID := seedAccountMembership(t, st, adminID, string(account.RoleAdmin))
		session := createTokenSession(t, st, adminID, accountID, time.Hour)
		key := bytes.Repeat([]byte{0x22}, 32)
		if _, err := st.CreateAPIToken(ctx, accountID, adminID, authn.HashToken(session),
			"consume-wins", 0, 10, randID(t), key); err != nil {
			t.Fatal(err)
		}
		barrier := installFlashTriggerBarrier(t, st, "DELETE")
		type consumeResult struct {
			raw string
			err error
		}
		consume := make(chan consumeResult, 1)
		go func() {
			raw, err := st.ConsumeTokenFlash(ctx, authn.HashToken(session), accountID, key)
			consume <- consumeResult{raw: raw, err: err}
		}()
		consumePID := waitForBlockedPID(t, st.DB(), barrier.holderPID)
		switchResult := make(chan error, 1)
		go func() { switchResult <- st.SelectSessionAccount(ctx, session, adminID, otherAccountID) }()
		if !waitForPostgresBlockers(ctx, st.DB(), consumePID, 1, 5*time.Second) {
			t.Fatal("session selection did not wait for flash consume")
		}
		barrier.release(t)
		got := <-consume
		if got.err != nil || !strings.HasPrefix(got.raw, "dr_") {
			t.Fatalf("consume winner = %q, %v", got.raw, got.err)
		}
		if err := <-switchResult; err != nil {
			t.Fatalf("select after consume: %v", err)
		}
		assertSessionAccounts(t, st, session, &otherAccountID, &otherAccountID)
		assertTokenMutationCounts(t, st, accountID, 1, 1, 0)
		if raw, err := st.ConsumeTokenFlash(ctx, authn.HashToken(session), accountID, key); err != nil || raw != "" {
			t.Fatalf("consumed old flash reappeared = %q, %v", raw, err)
		}
	})
}

func TestAPITokenAdmissionMixedVersionLockOrder(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, adminID := seedAuditAccount(t, st)
	session := createTokenSession(t, st, adminID, accountID, time.Hour)
	oldTx, err := st.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = oldTx.Rollback() })
	var oldPID int
	if err := oldTx.QueryRowContext(ctx, `
		SELECT pg_backend_pid() FROM pg_advisory_xact_lock(hashtext($1))`, accountID).
		Scan(&oldPID); err != nil {
		t.Fatal(err)
	}
	newResult := make(chan error, 1)
	requestID := randID(t)
	go func() {
		_, err := st.CreateAPIToken(ctx, accountID, adminID, authn.HashToken(session),
			"new-revision", 0, 1, requestID, bytes.Repeat([]byte{0x31}, 32))
		newResult <- err
	}()
	if !waitForPostgresBlockers(ctx, st.DB(), oldPID, 1, 5*time.Second) {
		t.Fatal("new token admission did not wait on old advisory lock")
	}
	oldRaw, err := authn.NewToken("dr_")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oldTx.ExecContext(ctx, `
		INSERT INTO devradar_api_token (tenant_id,name,token_hash)
		SELECT $1,'old-revision',$2
		WHERE (SELECT count(*) FROM devradar_api_token WHERE tenant_id=$1) < 1`,
		accountID, authn.HashToken(oldRaw)); err != nil {
		t.Fatalf("old-revision token insert deadlocked with new account lock: %v", err)
	}
	if err := oldTx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-newResult; !errors.Is(err, postgres.ErrAPITokenLimit) {
		t.Fatalf("new admission after old insert = %v, want ErrAPITokenLimit", err)
	}
	assertTokenMutationCounts(t, st, accountID, 1, 0, 0)
}

func selectSessionInOpenTransaction(
	t *testing.T,
	st *postgres.Store,
	rawSession, accountID string,
) (*sql.Tx, int) {
	t.Helper()
	tx, err := st.DB().BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	var pid int
	if err := tx.QueryRowContext(context.Background(), `
		UPDATE devradar_session
		SET tenant_id=$2,active_account_id=$2
		WHERE id=$1
		RETURNING pg_backend_pid()`, authn.HashToken(rawSession), accountID).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	return tx, pid
}

type flashTriggerBarrier struct {
	conn      *sql.Conn
	lockKey   int64
	holderPID int
}

func installFlashTriggerBarrier(t *testing.T, st *postgres.Store, operation string) flashTriggerBarrier {
	t.Helper()
	key, err := strconv.ParseInt(randID(t)[:15], 16, 64)
	if err != nil {
		t.Fatal(err)
	}
	functionName := "test_block_flash_" + strings.ToLower(operation)
	triggerName := functionName + "_trigger"
	statement := fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM pg_advisory_xact_lock(%d);
			RETURN %s;
		END $$;
		CREATE TRIGGER %s BEFORE %s ON devradar_session_token_flash
		FOR EACH ROW EXECUTE FUNCTION %s()`,
		functionName, key, map[string]string{"UPDATE": "NEW", "DELETE": "OLD"}[operation],
		triggerName, operation, functionName)
	if _, err := st.DB().ExecContext(context.Background(), statement); err != nil {
		t.Fatal(err)
	}
	conn, err := st.DB().Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.ExecContext(context.Background(), `SELECT pg_advisory_lock($1)`, key); err != nil {
		t.Fatal(err)
	}
	var pid int
	if err := conn.QueryRowContext(context.Background(), `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	return flashTriggerBarrier{conn: conn, lockKey: key, holderPID: pid}
}

func (b flashTriggerBarrier) release(t *testing.T) {
	t.Helper()
	var released bool
	if err := b.conn.QueryRowContext(context.Background(),
		`SELECT pg_advisory_unlock($1)`, b.lockKey).Scan(&released); err != nil || !released {
		t.Fatalf("release flash trigger barrier = %v/%v", released, err)
	}
}

func waitForBlockedPID(t *testing.T, db *sql.DB, holderPID int) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		var pid int
		err := db.QueryRowContext(ctx, `
			SELECT pid FROM pg_stat_activity
			WHERE $1=ANY(pg_blocking_pids(pid))
			ORDER BY pid LIMIT 1`, holderPID).Scan(&pid)
		if err == nil {
			return pid
		}
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

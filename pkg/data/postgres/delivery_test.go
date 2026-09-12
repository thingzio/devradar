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
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

func TestDeliveryMigrationSchemaAndIdempotency(t *testing.T) {
	st := isolatedStoreAtVersion(t, 31)
	applyMigrationFile(t, st, "sql/migrations/032_account_invitations.sql")
	applyMigrationFile(t, st, "sql/migrations/032_account_invitations.sql")
	var workerSlots int
	if err := st.DB().QueryRow(`SELECT count(*) FROM devradar_delivery_slot`).Scan(&workerSlots); err != nil || workerSlots != 5 {
		t.Fatalf("delivery worker slots=%d error=%v, want 5", workerSlots, err)
	}
	accountID, inviterID := seedAuditAccount(t, st)

	invitationID := insertDeliveryInvitation(t, st, accountID, inviterID, "invitee@example.com", 1)
	if _, err := st.DB().Exec(`
		INSERT INTO devradar_account_invitation
			(account_id,normalized_email,role,invited_by_user_id,token_hash,token_version,expires_at)
		VALUES ($1,'invitee@example.com','reader',$2,$3,1,now()+interval '7 days')`,
		accountID, inviterID, fmt.Sprintf("%064x", 2)); err == nil {
		t.Fatal("second pending invitation for account/email was accepted")
	}
	if _, err := st.DB().Exec(`
		UPDATE devradar_account_invitation SET revoked_at=now(),revoked_by_user_id=$2 WHERE id=$1`,
		invitationID, inviterID); err != nil {
		t.Fatalf("revoke first invitation: %v", err)
	}
	_ = insertDeliveryInvitation(t, st, accountID, inviterID, "invitee@example.com", 2)

	if _, err := st.DB().Exec(`
		INSERT INTO devradar_account_invitation
			(account_id,normalized_email,role,invited_by_user_id,token_hash,token_version,expires_at)
		VALUES ($1,'Mixed@Example.com','reader',$2,$3,1,now()+interval '7 days')`,
		accountID, inviterID, fmt.Sprintf("%064x", 3)); err == nil {
		t.Fatal("non-normalized invitation email was accepted")
	}
	if _, err := st.DB().Exec(`
		INSERT INTO devradar_account_invitation
			(account_id,normalized_email,role,invited_by_user_id,token_hash,token_version,expires_at)
		VALUES ($1,'role@example.com','owner',$2,$3,1,now()+interval '7 days')`,
		accountID, inviterID, fmt.Sprintf("%064x", 4)); err == nil {
		t.Fatal("invalid invitation role was accepted")
	}

	secondAccountID, secondInviterID := seedAuditAccount(t, st)
	secondInvitationID := insertDeliveryInvitation(t, st, secondAccountID, secondInviterID, "second@example.com", 1)
	for _, invalid := range []struct {
		name       string
		accountID  string
		invitation string
		version    int
		recipient  string
		payload    string
		key        string
	}{
		{name: "cross account", accountID: accountID, invitation: secondInvitationID, version: 1, recipient: "second@example.com", payload: "enc:ciphertext", key: "safe/cross-account"},
		{name: "wrong recipient", accountID: secondAccountID, invitation: secondInvitationID, version: 1, recipient: "wrong@example.com", payload: "enc:ciphertext", key: "safe/wrong-recipient"},
		{name: "wrong version", accountID: secondAccountID, invitation: secondInvitationID, version: 2, recipient: "second@example.com", payload: "enc:ciphertext", key: "safe/wrong-version"},
		{name: "plaintext", accountID: secondAccountID, invitation: secondInvitationID, version: 1, recipient: "second@example.com", payload: "raw-token", key: "safe/plaintext"},
		{name: "oversized ciphertext", accountID: secondAccountID, invitation: secondInvitationID, version: 1, recipient: "second@example.com", payload: "enc:" + strings.Repeat("x", 4093), key: "safe/oversized"},
		{name: "header unsafe idempotency", accountID: secondAccountID, invitation: secondInvitationID, version: 1, recipient: "second@example.com", payload: "enc:ciphertext", key: "unsafe\r\nheader"},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			if _, err := st.DB().Exec(`
				INSERT INTO devradar_delivery_outbox
					(account_id,kind,invitation_id,invitation_version,recipient,encrypted_payload,idempotency_key)
				VALUES ($1,'account_invitation',$2,$3,$4,$5,$6)`,
				invalid.accountID, invalid.invitation, invalid.version, invalid.recipient,
				invalid.payload, invalid.key); err == nil {
				t.Fatalf("invalid outbox row was accepted")
			}
		})
	}
	var outboxID string
	if err := st.DB().QueryRow(`
		INSERT INTO devradar_delivery_outbox
			(account_id,kind,invitation_id,invitation_version,recipient,encrypted_payload,idempotency_key)
		VALUES ($1,'account_invitation',$2,1,'second@example.com','enc:ciphertext','safe/correct')
		RETURNING id`, secondAccountID, secondInvitationID).Scan(&outboxID); err != nil {
		t.Fatalf("insert matching outbox row: %v", err)
	}
	if _, err := st.DB().Exec(`UPDATE devradar_delivery_outbox SET recipient='changed@example.com' WHERE id=$1`, outboxID); err == nil {
		t.Fatal("outbox identity recipient was mutable")
	}
	for _, state := range []string{"accepted", "revoked", "expired"} {
		t.Run("direct "+state, func(t *testing.T) {
			email := state + "-direct@example.com"
			id := insertDeliveryInvitation(t, st, secondAccountID, secondInviterID, email, 1)
			var stateErr error
			switch state {
			case "accepted":
				_, stateErr = st.DB().Exec(`UPDATE devradar_account_invitation SET accepted_at=now(),accepted_by_user_id=$2,updated_at=now() WHERE id=$1`, id, secondInviterID)
			case "revoked":
				_, stateErr = st.DB().Exec(`UPDATE devradar_account_invitation SET revoked_at=now(),revoked_by_user_id=$2,updated_at=now() WHERE id=$1`, id, secondInviterID)
			case "expired":
				_, stateErr = st.DB().Exec(`UPDATE devradar_account_invitation SET created_at=now()-interval '8 days',expires_at=now()-interval '1 day',updated_at=now() WHERE id=$1`, id)
			}
			if stateErr != nil {
				t.Fatalf("set invitation %s: %v", state, stateErr)
			}
			if _, err := st.DB().Exec(`
				INSERT INTO devradar_delivery_outbox
					(account_id,kind,invitation_id,invitation_version,recipient,encrypted_payload,idempotency_key)
				VALUES ($1,'account_invitation',$2,1,$3,'enc:ciphertext',$4)`,
				secondAccountID, id, email, "safe/direct/"+state); err == nil {
				t.Fatalf("direct %s invitation enqueue was accepted", state)
			}
		})
	}
}

func TestEnqueueInvitationDeliveryValidatesIdentityAndAuditAtomicity(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	ctx := context.Background()
	accountID, inviterID := seedAuditAccount(t, st)
	otherAccountID, _ := seedAuditAccount(t, st)

	invalidCases := []struct {
		name      string
		accountID string
		email     string
		version   int
		mutate    func(string)
	}{
		{name: "wrong account", accountID: otherAccountID, email: "wrong-account@example.com", version: 1},
		{name: "wrong recipient", accountID: accountID, email: "wrong@example.com", version: 1},
		{name: "wrong version", accountID: accountID, email: "version@example.com", version: 2},
		{name: "accepted", accountID: accountID, email: "accepted@example.com", version: 1, mutate: func(id string) {
			if _, err := st.DB().Exec(`UPDATE devradar_account_invitation SET accepted_at=now(),accepted_by_user_id=$2,updated_at=now() WHERE id=$1`, id, inviterID); err != nil {
				t.Fatalf("accept invitation: %v", err)
			}
		}},
		{name: "revoked", accountID: accountID, email: "revoked@example.com", version: 1, mutate: func(id string) {
			if _, err := st.DB().Exec(`UPDATE devradar_account_invitation SET revoked_at=now(),revoked_by_user_id=$2,updated_at=now() WHERE id=$1`, id, inviterID); err != nil {
				t.Fatalf("revoke invitation: %v", err)
			}
		}},
		{name: "expired", accountID: accountID, email: "expired@example.com", version: 1, mutate: func(id string) {
			if _, err := st.DB().Exec(`UPDATE devradar_account_invitation SET created_at=now()-interval '8 days',expires_at=now()-interval '1 day',updated_at=now() WHERE id=$1`, id); err != nil {
				t.Fatalf("expire invitation: %v", err)
			}
		}},
	}
	for _, test := range invalidCases {
		t.Run(test.name, func(t *testing.T) {
			actualEmail := test.email
			if test.name == "wrong recipient" {
				actualEmail = "recipient@example.com"
			}
			if test.name == "wrong version" {
				actualEmail = test.email
			}
			invitationID := insertDeliveryInvitation(t, st, accountID, inviterID, actualEmail, 1)
			if test.mutate != nil {
				test.mutate(invitationID)
			}
			tx, err := st.DB().BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback() }()
			_, err = st.EnqueueInvitationDelivery(ctx, tx, test.accountID, postgres.InvitationDelivery{
				InvitationID: invitationID, InvitationVersion: test.version, Recipient: test.email,
				EncryptedPayload: "enc:ciphertext", IdempotencyKey: "enqueue/invalid/" + randID(t),
			})
			if !errors.Is(err, postgres.ErrStaleDeliveryInvitation) {
				t.Fatalf("enqueue error = %v, want ErrStaleDeliveryInvitation", err)
			}
		})
	}

	invitationID := insertDeliveryInvitation(t, st, accountID, inviterID, "valid@example.com", 1)
	event := postgres.AuditEvent{Action: "invitation.delivery.enqueue", TargetType: "invitation",
		TargetID: invitationID, Outcome: "success", RequestID: randID(t)}
	err := st.WithAudit(ctx, accountID, account.Actor{Kind: account.ActorUser, UserID: inviterID}, event,
		func(tx *sql.Tx) error {
			_, err := st.EnqueueInvitationDelivery(ctx, tx, accountID, postgres.InvitationDelivery{
				InvitationID: invitationID, InvitationVersion: 1, Recipient: "valid@example.com",
				EncryptedPayload: "enc:ciphertext", IdempotencyKey: "enqueue/valid/" + randID(t),
			})
			return err
		})
	if err != nil {
		t.Fatalf("audited enqueue: %v", err)
	}
	if _, err := st.DB().Exec(`UPDATE devradar_account_invitation SET token_version=2,token_hash=$2,updated_at=now() WHERE id=$1`,
		invitationID, randID(t)+randID(t)); err != nil {
		t.Fatalf("rotate invitation: %v", err)
	}
	var oldRows int
	if err := st.DB().QueryRow(`SELECT count(*) FROM devradar_delivery_outbox WHERE invitation_id=$1 AND invitation_version=1`, invitationID).Scan(&oldRows); err != nil || oldRows != 1 {
		t.Fatalf("old delivery rows = %d, %v, want 1", oldRows, err)
	}

	rollbackInvitationID := insertDeliveryInvitation(t, st, accountID, inviterID, "rollback@example.com", 1)
	if _, err := st.DB().Exec(`ALTER TABLE devradar_audit_event ADD CONSTRAINT test_reject_delivery_audit CHECK (action <> 'forced.delivery.failure')`); err != nil {
		t.Fatalf("add forced audit failure: %v", err)
	}
	err = st.WithAudit(ctx, accountID, account.Actor{Kind: account.ActorUser, UserID: inviterID}, postgres.AuditEvent{
		Action: "forced.delivery.failure", TargetType: "invitation", TargetID: rollbackInvitationID,
		Outcome: "success", RequestID: randID(t),
	}, func(tx *sql.Tx) error {
		_, err := st.EnqueueInvitationDelivery(ctx, tx, accountID, postgres.InvitationDelivery{
			InvitationID: rollbackInvitationID, InvitationVersion: 1, Recipient: "rollback@example.com",
			EncryptedPayload: "enc:ciphertext", IdempotencyKey: "enqueue/rollback/" + randID(t),
		})
		return err
	})
	if err == nil {
		t.Fatal("forced audit failure returned nil")
	}
	var rolledBack int
	if err := st.DB().QueryRow(`SELECT count(*) FROM devradar_delivery_outbox WHERE invitation_id=$1`, rollbackInvitationID).Scan(&rolledBack); err != nil || rolledBack != 0 {
		t.Fatalf("rolled-back outbox rows = %d, %v", rolledBack, err)
	}
}

func TestDeliveryLeasesAreDisjointAndAttemptsIncrement(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	accountID, inviterID := seedAuditAccount(t, st)
	for i := 0; i < 8; i++ {
		invitationID := insertDeliveryInvitation(t, st, accountID, inviterID,
			fmt.Sprintf("worker-%d-%s@example.com", i, randID(t)[:8]), i+1)
		insertDeliveryOutbox(t, st, accountID, invitationID, i+1, time.Now().Add(-time.Minute))
	}

	type result struct {
		owner string
		rows  []postgres.Delivery
		err   error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for _, owner := range []string{"worker-a-" + randID(t), "worker-b-" + randID(t)} {
		wg.Add(1)
		go func(owner string) {
			defer wg.Done()
			<-start
			rows, err := st.LeaseDeliveries(context.Background(), owner, 4, time.Minute)
			results <- result{owner: owner, rows: rows, err: err}
		}(owner)
	}
	close(start)
	wg.Wait()
	close(results)

	seen := make(map[string]string)
	for result := range results {
		if result.err != nil || len(result.rows) != 4 {
			t.Fatalf("lease %s rows=%d err=%v", result.owner, len(result.rows), result.err)
		}
		for _, row := range result.rows {
			if previous := seen[row.ID]; previous != "" {
				t.Fatalf("delivery %s leased to %s and %s", row.ID, previous, result.owner)
			}
			seen[row.ID] = result.owner
			if row.AccountID != accountID || row.LeaseOwner != result.owner || row.AttemptCount != 1 || row.InvitationID == "" || row.InvitationVersion < 1 {
				t.Fatalf("leased delivery = %#v", row)
			}
		}
	}
}

func TestDeliveryWorkerSlotsBoundConcurrencyAndSurviveConnectionLoss(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	first, err := st.LeaseDeliverySlots(ctx, "execution-a", 5, 6*time.Minute)
	if err != nil || len(first) != 5 {
		t.Fatalf("first slot lease count=%d error=%v", len(first), err)
	}
	// Close every idle physical connection. Session advisory locks would vanish
	// here; durable slot rows must remain owned until explicit release/expiry.
	st.DB().SetMaxIdleConns(0)
	if err := st.DB().PingContext(ctx); err != nil {
		t.Fatalf("reconnect after leasing connection loss: %v", err)
	}
	second, err := st.LeaseDeliverySlots(ctx, "execution-b", 5, 6*time.Minute)
	if err != nil || len(second) != 0 {
		t.Fatalf("slots after connection loss count=%d error=%v, want 0", len(second), err)
	}

	stale := append([]postgres.DeliverySlot(nil), first...)
	stale[0].Generation++
	if err := st.ReleaseDeliverySlots(ctx, "execution-a", stale); !errors.Is(err, postgres.ErrStaleDeliverySlot) {
		t.Fatalf("stale generation release error=%v, want ErrStaleDeliverySlot", err)
	}
	if err := st.ReleaseDeliverySlots(ctx, "execution-a", first); err != nil {
		t.Fatalf("release slots: %v", err)
	}
	second, err = st.LeaseDeliverySlots(ctx, "execution-b", 5, 6*time.Minute)
	if err != nil || len(second) != 5 {
		t.Fatalf("slots after release count=%d error=%v, want 5", len(second), err)
	}
}

func TestDeliveryPoisonAttemptDoesNotRollbackHealthyLease(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	accountID, inviterID := seedAuditAccount(t, st)
	poisonInvitation := insertDeliveryInvitation(t, st, accountID, inviterID, "poison@example.com", 1)
	poisonID := insertDeliveryOutbox(t, st, accountID, poisonInvitation, 1, time.Now().Add(-2*time.Minute))
	if _, err := st.DB().Exec(`UPDATE devradar_delivery_outbox SET attempt_count=10000,first_attempt_at=now() WHERE id=$1`, poisonID); err != nil {
		t.Fatalf("seed poison attempt: %v", err)
	}
	healthyInvitation := insertDeliveryInvitation(t, st, accountID, inviterID, "healthy@example.com", 1)
	healthyID := insertDeliveryOutbox(t, st, accountID, healthyInvitation, 1, time.Now().Add(-time.Minute))
	rows, err := st.LeaseDeliveries(context.Background(), "poison-worker", 2, time.Minute)
	if err != nil || len(rows) != 1 || rows[0].ID != healthyID || rows[0].AttemptCount != 1 {
		t.Fatalf("healthy leases = %#v, %v", rows, err)
	}
	var status, payload, lastError string
	var attempts int
	if err := st.DB().QueryRow(`SELECT status,encrypted_payload,last_error,attempt_count FROM devradar_delivery_outbox WHERE id=$1`, poisonID).
		Scan(&status, &payload, &lastError, &attempts); err != nil {
		t.Fatalf("read poison delivery: %v", err)
	}
	if status != "permanently_failed" || payload != "" || lastError != "maximum delivery attempts exceeded" || attempts != 10000 {
		t.Fatalf("poison status=%q payload=%q error=%q attempts=%d", status, payload, lastError, attempts)
	}
}

func TestDeliveryZeroLeaseDoesNotRequireOwnerOrMutate(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	accountID, inviterID := seedAuditAccount(t, st)
	invitationID := insertDeliveryInvitation(t, st, accountID, inviterID,
		"zero-"+randID(t)[:8]+"@example.com", 1)
	deliveryID := insertDeliveryOutbox(t, st, accountID, invitationID, 1, time.Now().Add(-time.Minute))
	rows, err := st.LeaseDeliveries(context.Background(), "", 0, 0)
	if err != nil || len(rows) != 0 {
		t.Fatalf("zero lease = %#v, %v", rows, err)
	}
	var status string
	var attempts int
	if err := st.DB().QueryRow(`SELECT status,attempt_count FROM devradar_delivery_outbox WHERE id=$1`, deliveryID).
		Scan(&status, &attempts); err != nil {
		t.Fatalf("read zero-limit delivery: %v", err)
	}
	if status != "pending" || attempts != 0 {
		t.Fatalf("zero lease status=%q attempts=%d", status, attempts)
	}
}

func TestDeliveryExpiredLeaseRecoveryAndStateTransitions(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	accountID, inviterID := seedAuditAccount(t, st)
	invitationID := insertDeliveryInvitation(t, st, accountID, inviterID,
		"recovery-"+randID(t)[:8]+"@example.com", 1)
	deliveryID := insertDeliveryOutbox(t, st, accountID, invitationID, 1, time.Now().Add(-time.Minute))

	first, err := st.LeaseDeliveries(context.Background(), "expired-owner", 1, time.Minute)
	if err != nil || len(first) != 1 {
		t.Fatalf("first lease = %#v, %v", first, err)
	}
	if _, err := st.DB().Exec(`UPDATE devradar_delivery_outbox SET lease_expires_at=now()-interval '1 second' WHERE id=$1`, deliveryID); err != nil {
		t.Fatalf("expire first lease: %v", err)
	}
	second, err := st.LeaseDeliveries(context.Background(), "recovery-owner", 1, time.Minute)
	if err != nil || len(second) != 1 || second[0].ID != deliveryID || second[0].AttemptCount != 2 {
		t.Fatalf("recovered lease = %#v, %v", second, err)
	}
	if err := st.CompleteDelivery(context.Background(), accountID, deliveryID, "expired-owner", first[0].AttemptCount, "provider-old"); !errors.Is(err, postgres.ErrStaleDeliveryLease) {
		t.Fatalf("wrong-owner completion error = %v", err)
	}
	if err := st.RetryDelivery(context.Background(), accountID, deliveryID, "recovery-owner", second[0].AttemptCount, "temporary recipient-safe error", time.Hour); err != nil {
		t.Fatalf("retry delivery: %v", err)
	}
	if rows, err := st.LeaseDeliveries(context.Background(), "too-early", 1, time.Minute); err != nil || len(rows) != 0 {
		t.Fatalf("early retry lease = %#v, %v", rows, err)
	}
	if _, err := st.DB().Exec(`UPDATE devradar_delivery_outbox SET next_attempt_at=now()-interval '1 second' WHERE id=$1`, deliveryID); err != nil {
		t.Fatalf("make retry due: %v", err)
	}
	third, err := st.LeaseDeliveries(context.Background(), "final-owner", 1, time.Minute)
	if err != nil || len(third) != 1 || third[0].AttemptCount != 3 {
		t.Fatalf("third lease = %#v, %v", third, err)
	}
	if err := st.CompleteDelivery(context.Background(), accountID, deliveryID, "final-owner", third[0].AttemptCount, "provider-final"); err != nil {
		t.Fatalf("complete delivery: %v", err)
	}
	assertFinalDelivery(t, st, deliveryID, "delivered", "provider-final")
	if err := st.CompleteDelivery(context.Background(), accountID, deliveryID, "final-owner", third[0].AttemptCount, "provider-repeat"); !errors.Is(err, postgres.ErrStaleDeliveryLease) {
		t.Fatalf("repeated completion error = %v", err)
	}
}

func TestDeliveryAttemptFencesReusedLeaseOwner(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	accountID, inviterID := seedAuditAccount(t, st)
	invitationID := insertDeliveryInvitation(t, st, accountID, inviterID,
		"fence-"+randID(t)[:8]+"@example.com", 1)
	deliveryID := insertDeliveryOutbox(t, st, accountID, invitationID, 1, time.Now().Add(-time.Minute))
	const owner = "intentionally-reused-owner"
	first, err := st.LeaseDeliveries(context.Background(), owner, 1, time.Minute)
	if err != nil || len(first) != 1 {
		t.Fatalf("first lease = %#v, %v", first, err)
	}
	if _, err := st.DB().Exec(`UPDATE devradar_delivery_outbox SET lease_expires_at=now()-interval '1 second' WHERE id=$1`, deliveryID); err != nil {
		t.Fatalf("expire first lease: %v", err)
	}
	second, err := st.LeaseDeliveries(context.Background(), owner, 1, time.Minute)
	if err != nil || len(second) != 1 {
		t.Fatalf("second lease = %#v, %v", second, err)
	}
	if err := st.CompleteDelivery(context.Background(), accountID, deliveryID, owner, first[0].AttemptCount, "stale-provider"); !errors.Is(err, postgres.ErrStaleDeliveryLease) {
		t.Fatalf("stale generation completion error = %v", err)
	}
	if err := st.CompleteDelivery(context.Background(), accountID, deliveryID, owner, second[0].AttemptCount, "current-provider"); err != nil {
		t.Fatalf("current generation completion: %v", err)
	}
}

func TestDeliveryInvitationVersionRevalidation(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	accountID, inviterID := seedAuditAccount(t, st)
	invitationID := insertDeliveryInvitation(t, st, accountID, inviterID,
		"current-"+randID(t)[:8]+"@example.com", 1)
	current, err := st.DeliveryInvitationCurrent(context.Background(), accountID, invitationID, 1)
	if err != nil || !current {
		t.Fatalf("current invitation = %v, %v", current, err)
	}
	if _, err := st.DB().Exec(`UPDATE devradar_account_invitation SET token_version=2,token_hash=$2,updated_at=now() WHERE id=$1`,
		invitationID, randID(t)+randID(t)); err != nil {
		t.Fatalf("rotate invitation: %v", err)
	}
	current, err = st.DeliveryInvitationCurrent(context.Background(), accountID, invitationID, 1)
	if err != nil || current {
		t.Fatalf("stale invitation = %v, %v", current, err)
	}
}

func TestDeliveryAccountBoundaryFencesRevalidationAndTransitions(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	accountID, inviterID := seedAuditAccount(t, st)
	otherAccountID, _ := seedAuditAccount(t, st)
	invitationID := insertDeliveryInvitation(t, st, accountID, inviterID, "boundary@example.com", 1)
	if current, err := st.DeliveryInvitationCurrent(context.Background(), otherAccountID, invitationID, 1); err != nil || current {
		t.Fatalf("foreign revalidation = %v, %v", current, err)
	}

	for _, test := range []struct {
		name   string
		finish func(string, string, int) error
	}{
		{name: "complete", finish: func(id, owner string, attempt int) error {
			return st.CompleteDelivery(context.Background(), otherAccountID, id, owner, attempt, "provider")
		}},
		{name: "retry", finish: func(id, owner string, attempt int) error {
			return st.RetryDelivery(context.Background(), otherAccountID, id, owner, attempt, "temporary", time.Minute)
		}},
		{name: "permanent", finish: func(id, owner string, attempt int) error {
			return st.PermanentlyFailDelivery(context.Background(), otherAccountID, id, owner, attempt, "permanent")
		}},
		{name: "cancel", finish: func(id, owner string, attempt int) error {
			return st.CancelDelivery(context.Background(), otherAccountID, id, owner, attempt, "stale")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			invitation := insertDeliveryInvitation(t, st, accountID, inviterID,
				test.name+"-"+randID(t)[:8]+"@example.com", 1)
			id := insertDeliveryOutbox(t, st, accountID, invitation, 1, time.Now().Add(-time.Minute))
			owner := "boundary-" + randID(t)
			rows, err := st.LeaseDeliveries(context.Background(), owner, 1, time.Minute)
			if err != nil || len(rows) != 1 || rows[0].ID != id {
				t.Fatalf("lease = %#v, %v", rows, err)
			}
			if err := test.finish(id, owner, rows[0].AttemptCount); !errors.Is(err, postgres.ErrStaleDeliveryLease) {
				t.Fatalf("foreign transition error = %v", err)
			}
			var status string
			if err := st.DB().QueryRow(`SELECT status FROM devradar_delivery_outbox WHERE id=$1`, id).Scan(&status); err != nil || status != "leased" {
				t.Fatalf("status after foreign transition = %q, %v", status, err)
			}
			if err := st.CancelDelivery(context.Background(), accountID, id, owner, rows[0].AttemptCount, "test cleanup"); err != nil {
				t.Fatalf("cleanup transition: %v", err)
			}
		})
	}
}

func TestRetryDeliveryUsesBoundedDatabaseDelay(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	accountID, inviterID := seedAuditAccount(t, st)
	invitationID := insertDeliveryInvitation(t, st, accountID, inviterID, "retry-clock@example.com", 1)
	deliveryID := insertDeliveryOutbox(t, st, accountID, invitationID, 1, time.Now().Add(-time.Minute))
	rows, err := st.LeaseDeliveries(context.Background(), "retry-clock-owner", 1, time.Minute)
	if err != nil || len(rows) != 1 {
		t.Fatalf("lease = %#v, %v", rows, err)
	}
	for _, delay := range []time.Duration{0, -time.Second, 23*time.Hour + time.Nanosecond} {
		if err := st.RetryDelivery(context.Background(), accountID, deliveryID, "retry-clock-owner",
			rows[0].AttemptCount, "temporary", delay); err == nil {
			t.Fatalf("invalid delay %s was accepted", delay)
		}
	}
	var before time.Time
	if err := st.DB().QueryRow(`SELECT clock_timestamp()`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	const delay = 30 * time.Minute
	if err := st.RetryDelivery(context.Background(), accountID, deliveryID, "retry-clock-owner",
		rows[0].AttemptCount, "temporary", delay); err != nil {
		t.Fatalf("retry: %v", err)
	}
	var nextAttempt, after time.Time
	if err := st.DB().QueryRow(`SELECT next_attempt_at,clock_timestamp() FROM devradar_delivery_outbox WHERE id=$1`, deliveryID).
		Scan(&nextAttempt, &after); err != nil {
		t.Fatal(err)
	}
	if nextAttempt.Before(before.Add(delay)) || nextAttempt.After(after.Add(delay)) {
		t.Fatalf("next attempt %s not derived from DB interval [%s,%s]", nextAttempt, before.Add(delay), after.Add(delay))
	}
}

func TestDeliveryPermanentFailureAndCancellationScrubCiphertext(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	accountID, inviterID := seedAuditAccount(t, st)
	for _, test := range []struct {
		name   string
		status string
		finish func(context.Context, string, string, int, string) error
	}{
		{name: "permanent failure", status: "permanently_failed", finish: func(ctx context.Context, id, owner string, attempt int, recipient string) error {
			return st.PermanentlyFailDelivery(ctx, accountID, id, owner, attempt,
				"Authorization: Bearer re_super_secret "+recipient+" "+stringsRepeat("safe error ", 100))
		}},
		{name: "cancellation", status: "canceled", finish: func(ctx context.Context, id, owner string, attempt int, _ string) error {
			return st.CancelDelivery(ctx, accountID, id, owner, attempt, "stale invitation version")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			invitationID := insertDeliveryInvitation(t, st, accountID, inviterID,
				test.status+"-"+randID(t)[:8]+"@example.com", 1)
			deliveryID := insertDeliveryOutbox(t, st, accountID, invitationID, 1, time.Now().Add(-time.Minute))
			owner := "owner-" + randID(t)
			rows, err := st.LeaseDeliveries(context.Background(), owner, 1, time.Minute)
			if err != nil || len(rows) != 1 {
				t.Fatalf("lease = %#v, %v", rows, err)
			}
			if err := test.finish(context.Background(), deliveryID, owner, rows[0].AttemptCount, rows[0].Recipient); err != nil {
				t.Fatalf("finish: %v", err)
			}
			assertFinalDelivery(t, st, deliveryID, test.status, "")
		})
	}
}

func TestDeliveryUnicodeErrorIsTruncatedWithoutInvalidUTF8(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	accountID, inviterID := seedAuditAccount(t, st)
	invitationID := insertDeliveryInvitation(t, st, accountID, inviterID,
		"unicode-"+randID(t)[:8]+"@example.com", 1)
	deliveryID := insertDeliveryOutbox(t, st, accountID, invitationID, 1, time.Now().Add(-time.Minute))
	rows, err := st.LeaseDeliveries(context.Background(), "unicode-owner", 1, time.Minute)
	if err != nil || len(rows) != 1 {
		t.Fatalf("lease = %#v, %v", rows, err)
	}
	if err := st.PermanentlyFailDelivery(context.Background(), accountID, deliveryID, "unicode-owner",
		rows[0].AttemptCount, strings.Repeat("界", 600)); err != nil {
		t.Fatalf("persist unicode provider error: %v", err)
	}
}

func insertDeliveryInvitation(t *testing.T, st *postgres.Store, accountID, inviterID, email string, version int) string {
	t.Helper()
	var id string
	err := st.DB().QueryRow(`
		INSERT INTO devradar_account_invitation
			(account_id,normalized_email,role,invited_by_user_id,token_hash,token_version,expires_at)
		VALUES ($1,$2,'reader',$3,$4,$5,now()+interval '7 days') RETURNING id`,
		accountID, email, inviterID, randID(t)+randID(t), version).Scan(&id)
	if err != nil {
		t.Fatalf("insert invitation: %v", err)
	}
	return id
}

func insertDeliveryOutbox(t *testing.T, st *postgres.Store, accountID, invitationID string, version int, due time.Time) string {
	t.Helper()
	var recipient string
	if err := st.DB().QueryRow(`SELECT normalized_email FROM devradar_account_invitation WHERE id=$1`, invitationID).Scan(&recipient); err != nil {
		t.Fatalf("read invitation recipient: %v", err)
	}
	var id string
	err := st.DB().QueryRow(`
		INSERT INTO devradar_delivery_outbox
			(account_id,kind,invitation_id,invitation_version,recipient,encrypted_payload,idempotency_key,next_attempt_at)
		VALUES ($1,'account_invitation',$2,$3,$4,$5,$6,$7) RETURNING id`,
		accountID, invitationID, version, recipient, "enc:ciphertext", "idempotency/"+randID(t), due).Scan(&id)
	if err != nil {
		t.Fatalf("insert outbox: %v", err)
	}
	return id
}

func assertFinalDelivery(t *testing.T, st *postgres.Store, id, status, providerID string) {
	t.Helper()
	var gotStatus, encryptedPayload, recipient string
	var gotProviderID *string
	var leaseOwner *string
	var errorText *string
	if err := st.DB().QueryRow(`
		SELECT status,encrypted_payload,provider_id,lease_owner,last_error,recipient
		FROM devradar_delivery_outbox WHERE id=$1`, id).
		Scan(&gotStatus, &encryptedPayload, &gotProviderID, &leaseOwner, &errorText, &recipient); err != nil {
		t.Fatalf("read final delivery: %v", err)
	}
	if gotStatus != status || encryptedPayload != "" || leaseOwner != nil {
		t.Fatalf("final state status=%q ciphertext=%q lease=%v", gotStatus, encryptedPayload, leaseOwner)
	}
	if providerID != "" && (gotProviderID == nil || *gotProviderID != providerID) {
		t.Fatalf("provider ID = %v, want %q", gotProviderID, providerID)
	}
	if errorText != nil && len(*errorText) > 512 {
		t.Fatalf("last error length = %d", len(*errorText))
	}
	if errorText != nil && (strings.Contains(*errorText, "re_super_secret") ||
		strings.Contains(*errorText, recipient)) {
		t.Fatalf("last error retained a credential/recipient: %q", *errorText)
	}
}

func stringsRepeat(value string, count int) string {
	result := ""
	for range count {
		result += value
	}
	return result
}

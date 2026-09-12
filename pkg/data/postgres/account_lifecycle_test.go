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
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

func TestMembershipListIsAccountFiltered(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, adminID := seedAuditAccount(t, st)
	otherAccountID, _ := seedAuditAccount(t, st)
	memberID := seedAccountMember(t, st, accountID, account.RoleEditor, adminID)
	_ = seedAccountMember(t, st, otherAccountID, account.RoleReader, adminID)

	members, err := st.ListMembers(ctx, accountID)
	if err != nil {
		t.Fatalf("list members: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("members = %d, want 2", len(members))
	}
	for _, member := range members {
		if member.Account.ID != accountID || member.Membership.AccountID != accountID {
			t.Fatalf("cross-account member returned: %#v", member)
		}
	}
	if members[0].Actor.ID != adminID && members[1].Actor.ID != adminID {
		t.Fatalf("admin %s missing from %#v", adminID, members)
	}
	if members[0].Actor.ID != memberID && members[1].Actor.ID != memberID {
		t.Fatalf("member %s missing from %#v", memberID, members)
	}
}

func TestMembershipAdminEqualityAndLifecycle(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, creatorID := seedAuditAccount(t, st)
	peerAdminID := seedAccountMember(t, st, accountID, account.RoleAdmin, creatorID)
	actor := account.Actor{Kind: account.ActorUser, UserID: peerAdminID}
	var beforeRoleUpdate time.Time
	if err := st.DB().QueryRowContext(ctx, `
		SELECT updated_at FROM devradar_account_member WHERE account_id=$1 AND user_id=$2`,
		accountID, creatorID).Scan(&beforeRoleUpdate); err != nil {
		t.Fatalf("read role timestamp: %v", err)
	}

	if err := st.ChangeMemberRoleAudited(ctx, accountID, creatorID, account.RoleEditor, actor, randID(t)); err != nil {
		t.Fatalf("equal admin demote creator: %v", err)
	}
	assertMembershipState(t, st, accountID, creatorID, account.RoleEditor, false)
	assertMembershipAudit(t, st, accountID, "membership.role_change", creatorID)
	var afterRoleUpdate time.Time
	if err := st.DB().QueryRowContext(ctx, `
		SELECT updated_at FROM devradar_account_member WHERE account_id=$1 AND user_id=$2`,
		accountID, creatorID).Scan(&afterRoleUpdate); err != nil {
		t.Fatalf("read changed role timestamp: %v", err)
	}
	if !afterRoleUpdate.After(beforeRoleUpdate) {
		t.Fatalf("role updated_at = %s, want after %s", afterRoleUpdate, beforeRoleUpdate)
	}

	if err := st.ChangeMemberRoleAudited(ctx, accountID, creatorID, account.RoleEditor, actor, randID(t)); err != nil {
		t.Fatalf("unchanged role: %v", err)
	}
	if got := membershipAuditCount(t, st, accountID, "membership.role_change"); got != 1 {
		t.Fatalf("unchanged role audits = %d, want 1", got)
	}
	var credentialID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_api_token (tenant_id,name,token_hash,created_by_user_id)
		VALUES ($1,'creator credential',$2,$3) RETURNING id`, accountID, randID(t), creatorID).
		Scan(&credentialID); err != nil {
		t.Fatalf("seed attributed credential: %v", err)
	}

	if err := st.RevokeMembershipAudited(ctx, accountID, creatorID, actor, randID(t)); err != nil {
		t.Fatalf("equal admin revoke creator: %v", err)
	}
	assertMembershipState(t, st, accountID, creatorID, account.RoleEditor, true)
	assertMembershipAudit(t, st, accountID, "membership.revoke", creatorID)
	var revokedByUserID, credentialOwnerID string
	var revokedAt time.Time
	if err := st.DB().QueryRowContext(ctx, `
		SELECT revoked_by_user_id,revoked_at FROM devradar_account_member
		WHERE account_id=$1 AND user_id=$2`, accountID, creatorID).
		Scan(&revokedByUserID, &revokedAt); err != nil {
		t.Fatalf("read revocation attribution: %v", err)
	}
	if revokedByUserID != peerAdminID || revokedAt.IsZero() {
		t.Fatalf("revocation attribution = %s/%s, want %s/nonzero", revokedByUserID, revokedAt, peerAdminID)
	}
	if err := st.DB().QueryRowContext(ctx, `
		SELECT created_by_user_id FROM devradar_api_token WHERE id=$1`, credentialID).
		Scan(&credentialOwnerID); err != nil {
		t.Fatalf("read credential owner after revocation: %v", err)
	}
	if credentialOwnerID != creatorID {
		t.Fatalf("credential owner = %s, want preserved %s", credentialOwnerID, creatorID)
	}

	var lifecycleRows int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT count(*) FROM devradar_account_member WHERE account_id=$1 AND user_id=$2`,
		accountID, creatorID).Scan(&lifecycleRows); err != nil {
		t.Fatalf("count lifecycle rows: %v", err)
	}
	if lifecycleRows != 1 {
		t.Fatalf("lifecycle rows = %d, want 1", lifecycleRows)
	}
}

func TestMembershipEditorAndReaderCanLeave(t *testing.T) {
	for _, role := range []account.Role{account.RoleEditor, account.RoleReader} {
		t.Run(string(role), func(t *testing.T) {
			st := isolatedAdminProductHealthStore(t)
			ctx := context.Background()
			accountID, adminID := seedAuditAccount(t, st)
			userID := seedAccountMember(t, st, accountID, role, adminID)
			actor := account.Actor{Kind: account.ActorUser, UserID: userID}

			if err := st.LeaveAccountAudited(ctx, accountID, actor, randID(t)); err != nil {
				t.Fatalf("%s leave: %v", role, err)
			}
			assertMembershipState(t, st, accountID, userID, role, true)
			assertMembershipAudit(t, st, accountID, "membership.leave", userID)
			if _, err := st.GetAccess(ctx, userID, accountID); !errors.Is(err, postgres.ErrNotFound) {
				t.Fatalf("access after leave = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestMembershipCrossAccountAndRoleAuthorizationFailClosed(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, adminID := seedAuditAccount(t, st)
	otherAccountID, otherAdminID := seedAuditAccount(t, st)
	readerID := seedAccountMember(t, st, accountID, account.RoleReader, adminID)

	if err := st.ChangeMemberRoleAudited(ctx, accountID, readerID, account.RoleEditor,
		account.Actor{Kind: account.ActorUser, UserID: otherAdminID}, randID(t)); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("cross-account role change = %v, want ErrNotFound", err)
	}
	if err := st.RevokeMembershipAudited(ctx, accountID, adminID,
		account.Actor{Kind: account.ActorUser, UserID: readerID}, randID(t)); !errors.Is(err, postgres.ErrForbidden) {
		t.Fatalf("reader revoke = %v, want ErrForbidden", err)
	}
	if err := st.LeaveAccountAudited(ctx, otherAccountID,
		account.Actor{Kind: account.ActorUser, UserID: readerID}, randID(t)); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("cross-account leave = %v, want ErrNotFound", err)
	}
	if got := membershipAuditCount(t, st, accountID, "membership.role_change") +
		membershipAuditCount(t, st, accountID, "membership.revoke") +
		membershipAuditCount(t, st, otherAccountID, "membership.leave"); got != 0 {
		t.Fatalf("denied mutation audits = %d, want 0", got)
	}
}

func TestMembershipAuditFailureRollsBack(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, adminID := seedAuditAccount(t, st)
	memberID := seedAccountMember(t, st, accountID, account.RoleReader, adminID)
	if _, err := st.DB().ExecContext(ctx, `
		ALTER TABLE devradar_audit_event ADD CONSTRAINT test_reject_membership_role
		CHECK (action <> 'membership.role_change')`); err != nil {
		t.Fatalf("add audit failure: %v", err)
	}
	err := st.ChangeMemberRoleAudited(ctx, accountID, memberID, account.RoleEditor,
		account.Actor{Kind: account.ActorUser, UserID: adminID}, randID(t))
	if err == nil {
		t.Fatal("forced audit failure returned nil")
	}
	assertMembershipState(t, st, accountID, memberID, account.RoleReader, false)
}

func TestMembershipAccountNameRequiresUserAdminActor(t *testing.T) {
	for _, tc := range []struct {
		name  string
		actor func(*testing.T, *postgres.Store, string, string) account.Actor
	}{
		{
			name: "reader",
			actor: func(t *testing.T, st *postgres.Store, accountID, adminID string) account.Actor {
				return account.Actor{Kind: account.ActorUser,
					UserID: seedAccountMember(t, st, accountID, account.RoleReader, adminID)}
			},
		},
		{
			name: "api token",
			actor: func(t *testing.T, st *postgres.Store, accountID, _ string) account.Actor {
				var tokenID string
				if err := st.DB().QueryRowContext(context.Background(), `
					INSERT INTO devradar_api_token (tenant_id,name,token_hash)
					VALUES ($1,'name actor',$2) RETURNING id`, accountID, randID(t)).Scan(&tokenID); err != nil {
					t.Fatalf("seed API-token name actor: %v", err)
				}
				return account.Actor{Kind: account.ActorAPIToken, APITokenID: tokenID}
			},
		},
		{
			name: "platform",
			actor: func(_ *testing.T, _ *postgres.Store, _ string, adminID string) account.Actor {
				return account.Actor{Kind: account.ActorPlatform, UserID: adminID}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := isolatedAdminProductHealthStore(t)
			ctx := context.Background()
			accountID, adminID := seedAuditAccount(t, st)
			err := st.UpdateAccountNameAudited(ctx, accountID, "Unauthorized rename",
				tc.actor(t, st, accountID, adminID), randID(t))
			if !errors.Is(err, postgres.ErrForbidden) {
				t.Fatalf("unauthorized rename = %v, want ErrForbidden", err)
			}
			var name string
			var audits int
			if err := st.DB().QueryRowContext(ctx, `
				SELECT name,(SELECT count(*) FROM devradar_audit_event
				 WHERE account_id=$1 AND action='account.name.update')
				FROM devradar_tenant WHERE id=$1`, accountID).Scan(&name, &audits); err != nil {
				t.Fatalf("read rejected rename: %v", err)
			}
			if name != "Original" || audits != 0 {
				t.Fatalf("rejected rename state/audits = %q/%d, want Original/0", name, audits)
			}
		})
	}
}

func TestMembershipSuspendedActorDenied(t *testing.T) {
	operations := []struct {
		name string
		run  func(context.Context, *postgres.Store, string, string, string) error
	}{
		{"name", func(ctx context.Context, st *postgres.Store, accountID, actorID, _ string) error {
			return st.UpdateAccountNameAudited(ctx, accountID, "Suspended rename",
				account.Actor{Kind: account.ActorUser, UserID: actorID}, randRequestID())
		}},
		{"role", func(ctx context.Context, st *postgres.Store, accountID, actorID, targetID string) error {
			return st.ChangeMemberRoleAudited(ctx, accountID, targetID, account.RoleEditor,
				account.Actor{Kind: account.ActorUser, UserID: actorID}, randRequestID())
		}},
		{"revoke", func(ctx context.Context, st *postgres.Store, accountID, actorID, targetID string) error {
			return st.RevokeMembershipAudited(ctx, accountID, targetID,
				account.Actor{Kind: account.ActorUser, UserID: actorID}, randRequestID())
		}},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			st := isolatedAdminProductHealthStore(t)
			ctx := context.Background()
			accountID, adminID := seedAuditAccount(t, st)
			targetID := seedAccountMember(t, st, accountID, account.RoleReader, adminID)
			if _, err := st.DB().ExecContext(ctx,
				`UPDATE devradar_user SET status='suspended' WHERE id=$1`, adminID); err != nil {
				t.Fatalf("suspend actor: %v", err)
			}
			if err := operation.run(ctx, st, accountID, adminID, targetID); !errors.Is(err, postgres.ErrForbidden) {
				t.Fatalf("suspended actor %s = %v, want ErrForbidden", operation.name, err)
			}
			assertMembershipState(t, st, accountID, targetID, account.RoleReader, false)
			assertAccountNameAndMembershipAudits(t, st, accountID, "Original", 0)
		})
	}
}

func TestMembershipSuspendedAccountDenied(t *testing.T) {
	operations := []struct {
		name string
		run  func(context.Context, *postgres.Store, string, string, string) error
	}{
		{"name", func(ctx context.Context, st *postgres.Store, accountID, actorID, _ string) error {
			return st.UpdateAccountNameAudited(ctx, accountID, "Suspended account rename",
				account.Actor{Kind: account.ActorUser, UserID: actorID}, randRequestID())
		}},
		{"role", func(ctx context.Context, st *postgres.Store, accountID, actorID, targetID string) error {
			return st.ChangeMemberRoleAudited(ctx, accountID, targetID, account.RoleEditor,
				account.Actor{Kind: account.ActorUser, UserID: actorID}, randRequestID())
		}},
		{"revoke", func(ctx context.Context, st *postgres.Store, accountID, actorID, targetID string) error {
			return st.RevokeMembershipAudited(ctx, accountID, targetID,
				account.Actor{Kind: account.ActorUser, UserID: actorID}, randRequestID())
		}},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			st := isolatedAdminProductHealthStore(t)
			ctx := context.Background()
			accountID, adminID := seedAuditAccount(t, st)
			targetID := seedAccountMember(t, st, accountID, account.RoleReader, adminID)
			if _, err := st.DB().ExecContext(ctx,
				`UPDATE devradar_tenant SET status='suspended' WHERE id=$1`, accountID); err != nil {
				t.Fatalf("suspend account: %v", err)
			}
			if err := operation.run(ctx, st, accountID, adminID, targetID); !errors.Is(err, postgres.ErrNotFound) {
				t.Fatalf("suspended account %s = %v, want ErrNotFound", operation.name, err)
			}
			assertMembershipState(t, st, accountID, targetID, account.RoleReader, false)
			assertAccountNameAndMembershipAudits(t, st, accountID, "Original", 0)
		})
	}
}

func TestLastActiveAdminIgnoresSuspendedPeer(t *testing.T) {
	for _, operation := range membershipOperations() {
		t.Run(operation.name, func(t *testing.T) {
			st := isolatedAdminProductHealthStore(t)
			ctx := context.Background()
			accountID, activeAdminID := seedAuditAccount(t, st)
			suspendedAdminID := seedAccountMember(t, st, accountID, account.RoleAdmin, activeAdminID)
			if _, err := st.DB().ExecContext(ctx,
				`UPDATE devradar_user SET status='suspended' WHERE id=$1`, suspendedAdminID); err != nil {
				t.Fatalf("suspend peer admin: %v", err)
			}
			if err := operation.run(ctx, st, accountID, activeAdminID, activeAdminID); !errors.Is(err, postgres.ErrLastAdmin) {
				t.Fatalf("%s with only suspended peer = %v, want ErrLastAdmin", operation.name, err)
			}
			assertMembershipState(t, st, accountID, activeAdminID, account.RoleAdmin, false)
			if got := membershipMutationAuditCount(t, st, accountID); got != 0 {
				t.Fatalf("denied %s audits = %d, want 0", operation.name, got)
			}
		})
	}
}

func TestMembershipSuspendedTargetLifecycleRemainsAuthoritative(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, activeAdminID := seedAuditAccount(t, st)
	suspendedAdminID := seedAccountMember(t, st, accountID, account.RoleAdmin, activeAdminID)
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_user SET status='suspended' WHERE id=$1`, suspendedAdminID); err != nil {
		t.Fatalf("suspend target admin: %v", err)
	}
	actor := account.Actor{Kind: account.ActorUser, UserID: activeAdminID}
	if err := st.ChangeMemberRoleAudited(ctx, accountID, suspendedAdminID, account.RoleEditor,
		actor, randRequestID()); err != nil {
		t.Fatalf("demote suspended target: %v", err)
	}
	assertMembershipState(t, st, accountID, suspendedAdminID, account.RoleEditor, false)
	if err := st.RevokeMembershipAudited(ctx, accountID, suspendedAdminID, actor, randRequestID()); err != nil {
		t.Fatalf("revoke suspended target: %v", err)
	}
	assertMembershipState(t, st, accountID, suspendedAdminID, account.RoleEditor, true)
	var status string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT status FROM devradar_user WHERE id=$1`, suspendedAdminID).Scan(&status); err != nil {
		t.Fatalf("read suspended target: %v", err)
	}
	if status != "suspended" {
		t.Fatalf("target status = %q, want suspended", status)
	}
	if got := membershipMutationAuditCount(t, st, accountID); got != 2 {
		t.Fatalf("suspended target mutation audits = %d, want 2", got)
	}
}

func TestLastAdminConcurrentSelfMutationMatrix(t *testing.T) {
	const repeats = 3
	operations := membershipOperations()
	for _, first := range operations {
		for _, second := range operations {
			t.Run(first.name+"_"+second.name, func(t *testing.T) {
				for repeat := 0; repeat < repeats; repeat++ {
					st := isolatedAdminProductHealthStore(t)
					ctx := context.Background()
					accountID, firstAdminID := seedAuditAccount(t, st)
					secondAdminID := seedAccountMember(t, st, accountID, account.RoleAdmin, firstAdminID)
					results := runConcurrentMembershipOperations(ctx, st, accountID,
						first, firstAdminID, firstAdminID, second, secondAdminID, secondAdminID)
					var successes, lastAdminFailures int
					for _, err := range results {
						switch {
						case err == nil:
							successes++
						case errors.Is(err, postgres.ErrLastAdmin):
							lastAdminFailures++
						default:
							t.Fatalf("repeat %d %s/%s error = %v", repeat, first.name, second.name, err)
						}
					}
					if successes != 1 || lastAdminFailures != 1 {
						t.Fatalf("repeat %d %s/%s successes/last-admin = %d/%d, want 1/1",
							repeat, first.name, second.name, successes, lastAdminFailures)
					}
					assertUsableAdminAndAuditCounts(t, st, accountID, 1, 1)
				}
			})
		}
	}
}

func TestLastAdminConcurrentCrossTargetRevalidation(t *testing.T) {
	const repeats = 3
	operations := membershipOperations()[:2]
	for _, first := range operations {
		for _, second := range operations {
			t.Run(first.name+"_"+second.name, func(t *testing.T) {
				for repeat := 0; repeat < repeats; repeat++ {
					st := isolatedAdminProductHealthStore(t)
					ctx := context.Background()
					accountID, firstAdminID := seedAuditAccount(t, st)
					secondAdminID := seedAccountMember(t, st, accountID, account.RoleAdmin, firstAdminID)
					results := runConcurrentMembershipOperations(ctx, st, accountID,
						first, firstAdminID, secondAdminID, second, secondAdminID, firstAdminID)
					var successes, authorizationFailures int
					var authorizationFailure error
					for _, err := range results {
						switch {
						case err == nil:
							successes++
						case errors.Is(err, postgres.ErrForbidden), errors.Is(err, postgres.ErrNotFound):
							authorizationFailures++
							authorizationFailure = err
						default:
							t.Fatalf("repeat %d cross-target %s/%s error = %v",
								repeat, first.name, second.name, err)
						}
					}
					if successes != 1 || authorizationFailures != 1 {
						t.Fatalf("repeat %d cross-target %s/%s successes/authorization = %d/%d, want 1/1",
							repeat, first.name, second.name, successes, authorizationFailures)
					}
					expectedFailure := expectedPostLockAuthorizationError(t, st, accountID,
						firstAdminID, secondAdminID)
					if !errors.Is(authorizationFailure, expectedFailure) {
						t.Fatalf("repeat %d cross-target %s/%s authorization error = %v, want %v",
							repeat, first.name, second.name, authorizationFailure, expectedFailure)
					}
					assertUsableAdminAndAuditCounts(t, st, accountID, 1, 1)
				}
			})
		}
	}
}

type membershipOperation struct {
	name string
	run  func(context.Context, *postgres.Store, string, string, string) error
}

func membershipOperations() []membershipOperation {
	return []membershipOperation{
		{"demote", func(ctx context.Context, st *postgres.Store, accountID, actorID, targetID string) error {
			return st.ChangeMemberRoleAudited(ctx, accountID, targetID, account.RoleReader,
				account.Actor{Kind: account.ActorUser, UserID: actorID}, randRequestID())
		}},
		{"revoke", func(ctx context.Context, st *postgres.Store, accountID, actorID, targetID string) error {
			return st.RevokeMembershipAudited(ctx, accountID, targetID,
				account.Actor{Kind: account.ActorUser, UserID: actorID}, randRequestID())
		}},
		{"leave", func(ctx context.Context, st *postgres.Store, accountID, actorID, _ string) error {
			return st.LeaveAccountAudited(ctx, accountID,
				account.Actor{Kind: account.ActorUser, UserID: actorID}, randRequestID())
		}},
	}
}

func runConcurrentMembershipOperations(
	ctx context.Context,
	st *postgres.Store,
	accountID string,
	first membershipOperation,
	firstActorID, firstTargetID string,
	second membershipOperation,
	secondActorID, secondTargetID string,
) []error {
	start := make(chan struct{})
	results := make(chan error, 2)
	var ready, done sync.WaitGroup
	ready.Add(2)
	done.Add(2)
	run := func(operation membershipOperation, actorID, targetID string) {
		defer done.Done()
		ready.Done()
		<-start
		results <- operation.run(ctx, st, accountID, actorID, targetID)
	}
	go run(first, firstActorID, firstTargetID)
	go run(second, secondActorID, secondTargetID)
	ready.Wait()
	close(start)
	done.Wait()
	close(results)
	var operationErrors []error
	for err := range results {
		operationErrors = append(operationErrors, err)
	}
	return operationErrors
}

func seedAccountMember(t *testing.T, st *postgres.Store, accountID string, role account.Role, creatorID string) string {
	t.Helper()
	ctx := context.Background()
	email := fmt.Sprintf("member-%s@example.com", randID(t)[:12])
	var userID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_user (email,email_verified_at) VALUES ($1,now()) RETURNING id`, email).
		Scan(&userID); err != nil {
		t.Fatalf("seed member user: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_account_member (account_id,user_id,role,created_by_user_id)
		VALUES ($1,$2,$3,$4)`, accountID, userID, role, creatorID); err != nil {
		t.Fatalf("seed %s membership: %v", role, err)
	}
	return userID
}

func assertMembershipState(t *testing.T, st *postgres.Store, accountID, userID string, role account.Role, revoked bool) {
	t.Helper()
	var gotRole account.Role
	var gotRevoked bool
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT role,revoked_at IS NOT NULL FROM devradar_account_member
		WHERE account_id=$1 AND user_id=$2`, accountID, userID).Scan(&gotRole, &gotRevoked); err != nil {
		t.Fatalf("read membership state: %v", err)
	}
	if gotRole != role || gotRevoked != revoked {
		t.Fatalf("membership = %s/revoked=%v, want %s/%v", gotRole, gotRevoked, role, revoked)
	}
}

func assertMembershipAudit(t *testing.T, st *postgres.Store, accountID, action, targetUserID string) {
	t.Helper()
	var targetType, targetID string
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT target_type,target_id FROM devradar_audit_event
		WHERE account_id=$1 AND action=$2 ORDER BY id DESC LIMIT 1`, accountID, action).
		Scan(&targetType, &targetID); err != nil {
		t.Fatalf("read %s audit: %v", action, err)
	}
	if targetType != "membership" || targetID != targetUserID {
		t.Fatalf("%s target = %s/%s, want membership/%s", action, targetType, targetID, targetUserID)
	}
}

func membershipAuditCount(t *testing.T, st *postgres.Store, accountID, action string) int {
	t.Helper()
	var count int
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT count(*) FROM devradar_audit_event WHERE account_id=$1 AND action=$2`,
		accountID, action).Scan(&count); err != nil {
		t.Fatalf("count %s audits: %v", action, err)
	}
	return count
}

func membershipMutationAuditCount(t *testing.T, st *postgres.Store, accountID string) int {
	t.Helper()
	var count int
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT count(*) FROM devradar_audit_event
		WHERE account_id=$1 AND action LIKE 'membership.%'`, accountID).Scan(&count); err != nil {
		t.Fatalf("count membership mutation audits: %v", err)
	}
	return count
}

func assertAccountNameAndMembershipAudits(
	t *testing.T,
	st *postgres.Store,
	accountID, wantName string,
	wantAudits int,
) {
	t.Helper()
	var name string
	var audits int
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT name,(SELECT count(*) FROM devradar_audit_event
		 WHERE account_id=$1 AND (action='account.name.update' OR action LIKE 'membership.%'))
		FROM devradar_tenant WHERE id=$1`, accountID).Scan(&name, &audits); err != nil {
		t.Fatalf("read account name and audits: %v", err)
	}
	if name != wantName || audits != wantAudits {
		t.Fatalf("account name/audits = %q/%d, want %q/%d", name, audits, wantName, wantAudits)
	}
}

func assertUsableAdminAndAuditCounts(
	t *testing.T,
	st *postgres.Store,
	accountID string,
	wantAdmins, wantAudits int,
) {
	t.Helper()
	var admins int
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT count(*) FROM devradar_account_member m
		JOIN devradar_user u ON u.id=m.user_id
		WHERE m.account_id=$1 AND m.role='admin' AND m.revoked_at IS NULL
		  AND u.status='active'`, accountID).Scan(&admins); err != nil {
		t.Fatalf("count usable admins: %v", err)
	}
	if admins != wantAdmins {
		t.Fatalf("usable admins = %d, want %d", admins, wantAdmins)
	}
	if audits := membershipMutationAuditCount(t, st, accountID); audits != wantAudits {
		t.Fatalf("membership mutation audits = %d, want %d", audits, wantAudits)
	}
}

func expectedPostLockAuthorizationError(
	t *testing.T,
	st *postgres.Store,
	accountID, firstAdminID, secondAdminID string,
) error {
	t.Helper()
	rows, err := st.DB().QueryContext(context.Background(), `
		SELECT user_id,role,revoked_at IS NOT NULL
		FROM devradar_account_member
		WHERE account_id=$1 AND user_id IN ($2,$3)`, accountID, firstAdminID, secondAdminID)
	if err != nil {
		t.Fatalf("read post-lock membership states: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var userID string
		var role account.Role
		var revoked bool
		if err := rows.Scan(&userID, &role, &revoked); err != nil {
			t.Fatalf("scan post-lock membership state: %v", err)
		}
		if revoked {
			return postgres.ErrNotFound
		}
		if role != account.RoleAdmin {
			return postgres.ErrForbidden
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate post-lock membership states: %v", err)
	}
	t.Fatal("no demoted or revoked actor after cross-target race")
	return nil
}

func randRequestID() string {
	return "concurrent-request"
}

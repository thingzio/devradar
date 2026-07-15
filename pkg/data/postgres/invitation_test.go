package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/authn"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/secretbox"
)

var invitationKey = []byte("0123456789abcdef0123456789abcdef")

func TestInvitationCreateRefreshResendRevokeAndAtomicity(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	ctx := context.Background()
	accountID, adminID := seedAuditAccount(t, st)
	foreignAccountID, foreignAdminID := seedAuditAccount(t, st)
	actor := account.Actor{Kind: account.ActorUser, UserID: adminID}

	for _, role := range []account.Role{account.RoleAdmin, account.RoleEditor, account.RoleReader} {
		email := fmt.Sprintf("%s-%s@example.com", role, randID(t)[:8])
		invite, err := st.CreateOrRefreshInvitation(ctx, accountID, "  "+email+"  ", role,
			actor, randID(t), invitationKey)
		if err != nil {
			t.Fatalf("create %s invitation: %v", role, err)
		}
		if invite.Email != email || invite.Role != role || invite.TokenVersion != 1 {
			t.Fatalf("created invitation = %#v", invite)
		}
		assertInvitationSecret(t, st, invite)
	}

	email := "refresh-" + randID(t)[:8] + "@example.com"
	first, err := st.CreateOrRefreshInvitation(ctx, accountID, email, account.RoleReader,
		actor, randID(t), invitationKey)
	if err != nil {
		t.Fatal(err)
	}
	firstRaw := invitationRawToken(t, st, first)
	refreshed, err := st.CreateOrRefreshInvitation(ctx, accountID, email, account.RoleEditor,
		actor, randID(t), invitationKey)
	if err != nil {
		t.Fatalf("refresh invitation: %v", err)
	}
	if refreshed.ID != first.ID || refreshed.TokenVersion != 2 || refreshed.Role != account.RoleEditor {
		t.Fatalf("refreshed invitation = %#v, first %#v", refreshed, first)
	}
	if _, _, _, err := st.AcceptInvitation(ctx, first.ID, firstRaw, "", randID(t)); !errors.Is(err, postgres.ErrInvitationInvalid) {
		t.Fatalf("superseded token error = %v, want ErrInvitationInvalid", err)
	}
	if _, err := st.ResendInvitation(ctx, accountID, refreshed.ID, actor, randID(t), invitationKey); !errors.Is(err, postgres.ErrRateLimited) {
		t.Fatalf("immediate resend error = %v, want ErrRateLimited", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_account_invitation
		 SET created_at=created_at-interval '61 seconds',updated_at=now()-interval '61 seconds'
		 WHERE id=$1`, refreshed.ID); err != nil {
		t.Fatal(err)
	}
	resent, err := st.ResendInvitation(ctx, accountID, refreshed.ID, actor, randID(t), invitationKey)
	if err != nil || resent.TokenVersion != 3 {
		t.Fatalf("resend = %#v, %v", resent, err)
	}
	assertInvitationSecret(t, st, resent)

	if _, err := st.CreateOrRefreshInvitation(ctx, accountID, "foreign@example.com", account.RoleReader,
		account.Actor{Kind: account.ActorUser, UserID: foreignAdminID}, randID(t), invitationKey); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("foreign admin create error = %v", err)
	}
	memberID := seedInvitationUser(t, st, "member-"+randID(t)[:8]+"@example.com")
	if _, err := st.DB().ExecContext(ctx, `INSERT INTO devradar_account_member(account_id,user_id,role) VALUES($1,$2,'reader')`, accountID, memberID); err != nil {
		t.Fatal(err)
	}
	member, err := st.GetUser(ctx, memberID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateOrRefreshInvitation(ctx, accountID, member.Email, account.RoleEditor,
		actor, randID(t), invitationKey); !errors.Is(err, postgres.ErrActiveMember) {
		t.Fatalf("active member invitation error = %v", err)
	}

	if err := st.RevokeInvitation(ctx, foreignAccountID, resent.ID,
		account.Actor{Kind: account.ActorUser, UserID: foreignAdminID}, randID(t)); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("cross-account revoke error = %v", err)
	}
	if err := st.RevokeInvitation(ctx, accountID, resent.ID, actor, randID(t)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := st.PeekInvitation(ctx, resent.ID); !errors.Is(err, postgres.ErrInvitationInvalid) {
		t.Fatalf("peek revoked error = %v", err)
	}

	if _, err := st.DB().ExecContext(ctx, `ALTER TABLE devradar_audit_event ADD CONSTRAINT reject_invite_audit CHECK(action <> 'invitation.create') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	rollbackEmail := "rollback-" + randID(t)[:8] + "@example.com"
	if _, err := st.CreateOrRefreshInvitation(ctx, accountID, rollbackEmail, account.RoleReader,
		actor, randID(t), invitationKey); err == nil {
		t.Fatal("forced audit failure returned nil")
	}
	var invitationRows, outboxRows int
	if err := st.DB().QueryRowContext(ctx, `SELECT count(*) FROM devradar_account_invitation WHERE normalized_email=$1`, rollbackEmail).Scan(&invitationRows); err != nil {
		t.Fatal(err)
	}
	if err := st.DB().QueryRowContext(ctx, `SELECT count(*) FROM devradar_delivery_outbox WHERE recipient=$1`, rollbackEmail).Scan(&outboxRows); err != nil {
		t.Fatal(err)
	}
	if invitationRows != 0 || outboxRows != 0 {
		t.Fatalf("atomic rollback invitation/outbox = %d/%d", invitationRows, outboxRows)
	}
}

func TestInvitationDuplicateCreateIsNoOpAndDifferentRoleUsesRoleChange(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	ctx := context.Background()
	accountID, adminID := seedAuditAccount(t, st)
	actor := account.Actor{Kind: account.ActorUser, UserID: adminID}
	email := "duplicate-" + randID(t)[:8] + "@example.com"
	first, err := st.CreateOrRefreshInvitation(ctx, accountID, email, account.RoleReader,
		actor, randID(t), invitationKey)
	if err != nil {
		t.Fatal(err)
	}
	type snapshot struct {
		version          int
		hash             string
		expires, updated time.Time
		outboxes, audits int
	}
	readSnapshot := func() snapshot {
		t.Helper()
		var got snapshot
		if err := st.DB().QueryRowContext(ctx, `
			SELECT i.token_version,i.token_hash,i.expires_at,i.updated_at,
			       (SELECT count(*) FROM devradar_delivery_outbox d
			        WHERE d.account_id=i.account_id AND d.invitation_id=i.id),
			       (SELECT count(*) FROM devradar_audit_event a
			        WHERE a.account_id=i.account_id AND a.target_type='invitation' AND a.target_id=i.id::text)
			FROM devradar_account_invitation i
			WHERE i.account_id=$1 AND i.id=$2`, accountID, first.ID).Scan(
			&got.version, &got.hash, &got.expires, &got.updated, &got.outboxes, &got.audits); err != nil {
			t.Fatalf("read invitation snapshot: %v", err)
		}
		return got
	}

	before := readSnapshot()
	duplicate, err := st.CreateOrRefreshInvitation(ctx, accountID,
		"  "+strings.ToUpper(email)+"  ", account.RoleReader, actor, randID(t), invitationKey)
	if err != nil {
		t.Fatalf("duplicate create: %v", err)
	}
	after := readSnapshot()
	if duplicate.ID != first.ID || duplicate.TokenVersion != first.TokenVersion ||
		!duplicate.ExpiresAt.Equal(first.ExpiresAt) || !duplicate.UpdatedAt.Equal(first.UpdatedAt) {
		t.Fatalf("duplicate invitation changed: first=%#v duplicate=%#v", first, duplicate)
	}
	if after.version != before.version || after.hash != before.hash ||
		!after.expires.Equal(before.expires) || !after.updated.Equal(before.updated) ||
		after.outboxes != before.outboxes || after.audits != before.audits {
		t.Fatalf("duplicate snapshot changed: before=%#v after=%#v", before, after)
	}

	changed, err := st.CreateOrRefreshInvitation(ctx, accountID, email, account.RoleEditor,
		actor, randID(t), invitationKey)
	if err != nil {
		t.Fatalf("different-role create: %v", err)
	}
	if changed.ID != first.ID || changed.Role != account.RoleEditor || changed.TokenVersion != first.TokenVersion+1 {
		t.Fatalf("different-role invitation = %#v, first=%#v", changed, first)
	}
	var action string
	if err := st.DB().QueryRowContext(ctx, `
		SELECT action FROM devradar_audit_event
		WHERE account_id=$1 AND target_type='invitation' AND target_id=$2
		ORDER BY id DESC LIMIT 1`, accountID, first.ID).Scan(&action); err != nil {
		t.Fatalf("read different-role audit: %v", err)
	}
	if action != "invitation.role_change" {
		t.Fatalf("different-role audit action = %q, want invitation.role_change", action)
	}
}

func TestListInvitationsReportsSafeCurrentDeliveryState(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	ctx := context.Background()
	accountID, adminID := seedAuditAccount(t, st)
	foreignAccountID, foreignAdminID := seedAuditAccount(t, st)
	actor := account.Actor{Kind: account.ActorUser, UserID: adminID}
	foreignActor := account.Actor{Kind: account.ActorUser, UserID: foreignAdminID}

	create := func(email string, invitationActor account.Actor, targetAccountID string) *postgres.Invitation {
		t.Helper()
		invite, err := st.CreateOrRefreshInvitation(ctx, targetAccountID, email, account.RoleReader,
			invitationActor, randID(t), invitationKey)
		if err != nil {
			t.Fatalf("create %s: %v", email, err)
		}
		return invite
	}
	setDelivered := func(invite *postgres.Invitation) {
		t.Helper()
		if _, err := st.DB().ExecContext(ctx, `
			UPDATE devradar_delivery_outbox
			SET status='delivered',encrypted_payload='',provider_id='provider-safe',
			    delivered_at=clock_timestamp(),updated_at=clock_timestamp()
			WHERE account_id=$1 AND invitation_id=$2 AND invitation_version=$3`,
			invite.AccountID, invite.ID, invite.TokenVersion); err != nil {
			t.Fatalf("deliver %s: %v", invite.Email, err)
		}
	}

	current := create("current-"+randID(t)[:8]+"@example.com", actor, accountID)
	setDelivered(current)
	current, err := st.CreateOrRefreshInvitation(ctx, accountID, current.Email, account.RoleEditor,
		actor, randID(t), invitationKey)
	if err != nil {
		t.Fatalf("rotate current invitation: %v", err)
	}
	retrying := create("retrying-"+randID(t)[:8]+"@example.com", actor, accountID)
	if _, err := st.DB().ExecContext(ctx, `
		UPDATE devradar_delivery_outbox
		SET attempt_count=1,first_attempt_at=clock_timestamp(),last_error='provider bearer secret',
		    updated_at=clock_timestamp()
		WHERE account_id=$1 AND invitation_id=$2 AND invitation_version=$3`,
		accountID, retrying.ID, retrying.TokenVersion); err != nil {
		t.Fatalf("mark retrying: %v", err)
	}
	failed := create("failed-"+randID(t)[:8]+"@example.com", actor, accountID)
	if _, err := st.DB().ExecContext(ctx, `
		UPDATE devradar_delivery_outbox
		SET status='permanently_failed',encrypted_payload='',last_error='provider bearer secret',
		    permanently_failed_at=clock_timestamp(),updated_at=clock_timestamp()
		WHERE account_id=$1 AND invitation_id=$2 AND invitation_version=$3`,
		accountID, failed.ID, failed.TokenVersion); err != nil {
		t.Fatalf("mark failed: %v", err)
	}
	sent := create("sent-"+randID(t)[:8]+"@example.com", actor, accountID)
	setDelivered(sent)
	foreign := create("foreign-"+randID(t)[:8]+"@example.com", foreignActor, foreignAccountID)
	setDelivered(foreign)

	invitations, err := st.ListInvitations(ctx, accountID)
	if err != nil {
		t.Fatalf("list invitations: %v", err)
	}
	if len(invitations) != 4 {
		t.Fatalf("listed invitations = %d, want 4: %#v", len(invitations), invitations)
	}
	states := make(map[string]postgres.InvitationDeliveryState, len(invitations))
	for _, invitation := range invitations {
		states[invitation.Email] = invitation.DeliveryState
	}
	for email, want := range map[string]postgres.InvitationDeliveryState{
		current.Email:  postgres.InvitationDeliveryQueued,
		retrying.Email: postgres.InvitationDeliveryRetrying,
		failed.Email:   postgres.InvitationDeliveryFailed,
		sent.Email:     postgres.InvitationDeliverySent,
	} {
		if got := states[email]; got != want {
			t.Errorf("delivery state for %s = %q, want %q", email, got, want)
		}
	}
	if _, exists := states[foreign.Email]; exists {
		t.Fatalf("foreign invitation exposed: %#v", invitations)
	}
	foreignInvitations, err := st.ListInvitations(ctx, foreignAccountID)
	if err != nil || len(foreignInvitations) != 1 ||
		foreignInvitations[0].DeliveryState != postgres.InvitationDeliverySent {
		t.Fatalf("foreign invitation state = %#v, %v", foreignInvitations, err)
	}
}

func TestInvitationPeekAcceptIdentityMembershipAndConcurrency(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	ctx := context.Background()
	accountID, adminID := seedAuditAccount(t, st)
	actor := account.Actor{Kind: account.ActorUser, UserID: adminID}
	email := "new-" + randID(t)[:8] + "@example.com"
	invite, err := st.CreateOrRefreshInvitation(ctx, accountID, email, account.RoleEditor,
		actor, randID(t), invitationKey)
	if err != nil {
		t.Fatal(err)
	}
	raw := invitationRawToken(t, st, invite)
	peeked, err := st.PeekInvitation(ctx, invite.ID)
	if err != nil || peeked.ID != invite.ID || peeked.AccountName == "" || peeked.InvitedByEmail == "" {
		t.Fatalf("peek = %#v, %v", peeked, err)
	}
	var acceptedBefore int
	if err := st.DB().QueryRowContext(ctx, `SELECT count(*) FROM devradar_account_invitation WHERE id=$1 AND accepted_at IS NOT NULL`, invite.ID).Scan(&acceptedBefore); err != nil || acceptedBefore != 0 {
		t.Fatalf("GET-like peek consumed invitation: count=%d err=%v", acceptedBefore, err)
	}

	start := make(chan struct{})
	type result struct {
		userID   string
		acctID   string
		consumed bool
		err      error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			user, acct, consumed, err := st.AcceptInvitation(ctx, invite.ID, raw, "", randID(t))
			res := result{consumed: consumed, err: err}
			if user != nil {
				res.userID = user.ID
			}
			if acct != nil {
				res.acctID = acct.ID
			}
			results <- res
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	var first result
	var consumed int
	for res := range results {
		if res.err != nil {
			t.Fatalf("concurrent accept: %v", res.err)
		}
		if first.userID == "" {
			first = res
		} else if res.userID != first.userID || res.acctID != first.acctID {
			t.Fatalf("accept results differ: %#v / %#v", first, res)
		}
		if res.consumed {
			consumed++
		}
	}
	if consumed != 1 {
		t.Fatalf("concurrent consumed count = %d, want 1", consumed)
	}
	if first.acctID != accountID {
		t.Fatalf("accepted account = %s, want %s", first.acctID, accountID)
	}
	var accounts, memberships, audits, identities int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT (SELECT count(*) FROM devradar_tenant),
		       (SELECT count(*) FROM devradar_account_member WHERE account_id=$1 AND user_id=$2 AND role='editor' AND revoked_at IS NULL),
		       (SELECT count(*) FROM devradar_audit_event WHERE account_id=$1 AND action='invitation.accept'),
		       (SELECT count(*) FROM devradar_identity WHERE provider='magiclink' AND subject=$3 AND user_id=$2)`,
		accountID, first.userID, email).Scan(&accounts, &memberships, &audits, &identities); err != nil {
		t.Fatal(err)
	}
	if accounts != 1 || memberships != 1 || audits != 1 || identities != 1 {
		t.Fatalf("accept state accounts/memberships/audits/identities = %d/%d/%d/%d", accounts, memberships, audits, identities)
	}

	differentID := seedInvitationUser(t, st, "different-"+randID(t)[:8]+"@example.com")
	other, err := st.CreateOrRefreshInvitation(ctx, accountID, "existing-"+randID(t)[:8]+"@example.com", account.RoleReader, actor, randID(t), invitationKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := st.AcceptInvitation(ctx, other.ID, invitationRawToken(t, st, other), differentID, randID(t)); !errors.Is(err, postgres.ErrInvitationEmailMismatch) {
		t.Fatalf("different signed-in email error = %v", err)
	}
}

func TestInvitationAcceptanceExpiryRevocationAndReactivation(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	ctx := context.Background()
	accountID, adminID := seedAuditAccount(t, st)
	actor := account.Actor{Kind: account.ActorUser, UserID: adminID}

	email := "reactivate-" + randID(t)[:8] + "@example.com"
	userID := seedInvitationUser(t, st, email)
	if _, err := st.DB().ExecContext(ctx, `INSERT INTO devradar_account_member(account_id,user_id,role,revoked_at) VALUES($1,$2,'reader',now())`, accountID, userID); err != nil {
		t.Fatal(err)
	}
	invite, err := st.CreateOrRefreshInvitation(ctx, accountID, email, account.RoleAdmin, actor, randID(t), invitationKey)
	if err != nil {
		t.Fatal(err)
	}
	user, acct, consumed, err := st.AcceptInvitation(ctx, invite.ID, invitationRawToken(t, st, invite), userID, randID(t))
	if err != nil || !consumed || user.ID != userID || acct.ID != accountID {
		t.Fatalf("reactivate accept = %#v %#v consumed=%t %v", user, acct, consumed, err)
	}
	access, err := st.GetAccess(ctx, userID, accountID)
	if err != nil || access.Membership.Role != account.RoleAdmin || access.Membership.RevokedAt != nil {
		t.Fatalf("reactivated access = %#v, %v", access, err)
	}

	for _, tc := range []struct {
		name string
		set  string
		want error
	}{
		{"expired", `created_at=now()-interval '8 days',expires_at=now()-interval '1 day',updated_at=now()`, postgres.ErrInvitationExpired},
		{"revoked", `revoked_at=now(),revoked_by_user_id=invited_by_user_id,updated_at=now()`, postgres.ErrInvitationInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testEmail := tc.name + "-" + randID(t)[:8] + "@example.com"
			pending, err := st.CreateOrRefreshInvitation(ctx, accountID, testEmail, account.RoleReader, actor, randID(t), invitationKey)
			if err != nil {
				t.Fatal(err)
			}
			raw := invitationRawToken(t, st, pending)
			if _, err := st.DB().ExecContext(ctx, `UPDATE devradar_account_invitation SET `+tc.set+` WHERE id=$1`, pending.ID); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := st.AcceptInvitation(ctx, pending.ID, raw, "", randID(t)); !errors.Is(err, tc.want) {
				t.Fatalf("accept error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestInvitationAcceptanceAuditFailureRollsBackIdentityMembershipAndState(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	ctx := context.Background()
	accountID, adminID := seedAuditAccount(t, st)
	email := "accept-rollback-" + randID(t)[:8] + "@example.com"
	invite, err := st.CreateOrRefreshInvitation(ctx, accountID, email, account.RoleReader,
		account.Actor{Kind: account.ActorUser, UserID: adminID}, randID(t), invitationKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(ctx, `ALTER TABLE devradar_audit_event ADD CONSTRAINT reject_accept_audit CHECK(action <> 'invitation.accept') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := st.AcceptInvitation(ctx, invite.ID, invitationRawToken(t, st, invite), "", randID(t)); err == nil {
		t.Fatal("forced acceptance audit failure returned nil")
	}
	var users, identities, members, accepted int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT (SELECT count(*) FROM devradar_user WHERE email=$1),
		       (SELECT count(*) FROM devradar_identity WHERE provider='magiclink' AND subject=$1),
		       (SELECT count(*) FROM devradar_account_member m JOIN devradar_user u ON u.id=m.user_id WHERE m.account_id=$2 AND u.email=$1),
		       (SELECT count(*) FROM devradar_account_invitation WHERE id=$3 AND accepted_at IS NOT NULL)`,
		email, accountID, invite.ID).Scan(&users, &identities, &members, &accepted); err != nil {
		t.Fatal(err)
	}
	if users != 0 || identities != 0 || members != 0 || accepted != 0 {
		t.Fatalf("accept rollback users/identities/members/accepted = %d/%d/%d/%d", users, identities, members, accepted)
	}
}

func TestInvitationAcceptedTokenReplayDoesNotConsumeAgain(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	ctx := context.Background()
	accountID, adminID := seedAuditAccount(t, st)
	invite, err := st.CreateOrRefreshInvitation(ctx, accountID,
		"replay-"+randID(t)[:8]+"@example.com", account.RoleReader,
		account.Actor{Kind: account.ActorUser, UserID: adminID}, randID(t), invitationKey)
	if err != nil {
		t.Fatal(err)
	}
	raw := invitationRawToken(t, st, invite)
	user, acct, consumed, err := st.AcceptInvitation(ctx, invite.ID, raw, "", randID(t))
	if err != nil || !consumed {
		t.Fatalf("first accept consumed=%t err=%v", consumed, err)
	}
	replayedUser, replayedAccount, replayed, err := st.AcceptInvitation(ctx, invite.ID, raw, "", randID(t))
	if err != nil || replayed || replayedUser.ID != user.ID || replayedAccount.ID != acct.ID {
		t.Fatalf("replay user/account/consumed/error = %s/%s/%t/%v",
			replayedUser.ID, replayedAccount.ID, replayed, err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		UPDATE devradar_account_invitation
		SET created_at=created_at-interval '8 days',expires_at=now()-interval '1 day',updated_at=now()
		WHERE id=$1`, invite.ID); err != nil {
		t.Fatal(err)
	}
	_, _, replayed, err = st.AcceptInvitation(ctx, invite.ID, raw, "", randID(t))
	if err != nil || replayed {
		t.Fatalf("expired accepted replay consumed=%t err=%v", replayed, err)
	}
	var memberships, audits int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT (SELECT count(*) FROM devradar_account_member WHERE account_id=$1 AND user_id=$2),
		       (SELECT count(*) FROM devradar_audit_event WHERE account_id=$1 AND action='invitation.accept')`,
		accountID, user.ID).Scan(&memberships, &audits); err != nil {
		t.Fatal(err)
	}
	if memberships != 1 || audits != 1 {
		t.Fatalf("replay memberships/audits = %d/%d, want 1/1", memberships, audits)
	}
}

func assertInvitationSecret(t *testing.T, st *postgres.Store, invitation *postgres.Invitation) {
	t.Helper()
	raw := invitationRawToken(t, st, invitation)
	if authn.HashToken(raw) == raw || len(raw) != 64 {
		t.Fatalf("unexpected raw token shape: len=%d", len(raw))
	}
	var storedHash string
	if err := st.DB().QueryRow(`SELECT token_hash FROM devradar_account_invitation WHERE id=$1`, invitation.ID).Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if storedHash != authn.HashToken(raw) || storedHash == raw {
		t.Fatal("invitation did not store only the token hash")
	}
}

func invitationRawToken(t *testing.T, st *postgres.Store, invitation *postgres.Invitation) string {
	t.Helper()
	var encrypted, key string
	if err := st.DB().QueryRow(`
		SELECT encrypted_payload,idempotency_key FROM devradar_delivery_outbox
		WHERE invitation_id=$1 AND invitation_version=$2`, invitation.ID, invitation.TokenVersion).
		Scan(&encrypted, &key); err != nil {
		t.Fatalf("read invitation delivery: %v", err)
	}
	raw, err := secretbox.Open(invitationKey, encrypted, []byte(key))
	if err != nil {
		t.Fatalf("decrypt invitation token: %v", err)
	}
	return string(raw)
}

func seedInvitationUser(t *testing.T, st *postgres.Store, email string) string {
	t.Helper()
	var userID string
	if err := st.DB().QueryRow(`INSERT INTO devradar_user(email,email_verified_at) VALUES($1,now()) RETURNING id`, email).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	return userID
}

func TestInvitationTTLIsSevenDays(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	accountID, adminID := seedAuditAccount(t, st)
	invite, err := st.CreateOrRefreshInvitation(context.Background(), accountID,
		"ttl-"+randID(t)[:8]+"@example.com", account.RoleReader,
		account.Actor{Kind: account.ActorUser, UserID: adminID}, randID(t), invitationKey)
	if err != nil {
		t.Fatal(err)
	}
	ttl := invite.ExpiresAt.Sub(invite.UpdatedAt)
	if ttl < 7*24*time.Hour-time.Second || ttl > 7*24*time.Hour+time.Second {
		t.Fatalf("invitation TTL = %s, want seven days", ttl)
	}
}

func TestInvitationSharingCutoverReconcilesVerifiesAndPurges(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	ctx := context.Background()
	var accountID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant(email,name) VALUES($1,'') RETURNING id`,
		"cutover-"+randID(t)[:8]+"@example.com").Scan(&accountID); err != nil {
		t.Fatal(err)
	}
	if err := st.VerifyAccountSharingReady(ctx); err == nil {
		t.Fatal("incomplete compatibility account passed sharing verification")
	}
	if err := st.ReconcileLegacyAccounts(ctx); err != nil {
		t.Fatalf("reconcile sharing state: %v", err)
	}
	if err := st.VerifyAccountSharingReady(ctx); err != nil {
		t.Fatalf("verify reconciled sharing state: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO devradar_token_flash(tenant_id,value,expires_at) VALUES($1,'legacy',now()+interval '1 minute')`, accountID); err != nil {
		t.Fatal(err)
	}
	if err := st.PurgeLegacyTokenFlashes(ctx); err != nil {
		t.Fatal(err)
	}
	var flashes int
	if err := st.DB().QueryRowContext(ctx, `SELECT count(*) FROM devradar_token_flash`).Scan(&flashes); err != nil || flashes != 0 {
		t.Fatalf("legacy flashes = %d, %v", flashes, err)
	}
}

func TestInvitationSharingCutoverAcceptsModernDirectAccount(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	ctx := context.Background()
	identity := account.VerifiedIdentity{
		Provider: "github", Subject: "modern-" + randID(t),
		Email: "modern-" + randID(t)[:8] + "@example.com",
	}
	user, acct, err := st.ResolveDirectIdentity(ctx, identity)
	if err != nil || user == nil || acct == nil {
		t.Fatalf("resolve modern account = %#v %#v %v", user, acct, err)
	}
	if err := st.ReconcileLegacyAccounts(ctx); err != nil {
		t.Fatalf("reconcile modern account: %v", err)
	}
	if err := st.VerifyAccountSharingReady(ctx); err != nil {
		t.Fatalf("modern account rejected by sharing readiness: %v", err)
	}
}

func TestInvitationSharingCutoverRejectsOwnerlessIdentityWithoutLegacyAccount(t *testing.T) {
	st := isolatedStoreAtVersion(t, 32)
	ctx := context.Background()
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_identity(tenant_id,user_id,provider,subject,email)
		VALUES(NULL,NULL,'github',$1,$2)`, "ownerless-"+randID(t),
		"ownerless-"+randID(t)[:8]+"@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := st.VerifyAccountSharingReady(ctx); err == nil {
		t.Fatal("ownerless modern identity passed sharing readiness")
	}
}

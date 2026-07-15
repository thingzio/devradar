package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

func TestAdminAccountsListSearchFieldsAndMemberIsolation(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, initialAdminID := seedAuditAccount(t, st)
	otherAccountID, otherAdminID := seedAuditAccount(t, st)
	search := "member-search-" + randID(t)[:8]
	memberEmail := search + "@example.com"
	var memberID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_user (email,email_verified_at)
		VALUES ($1,now()) RETURNING id`, memberEmail).Scan(&memberID); err != nil {
		t.Fatalf("seed searchable member: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_account_member (account_id,user_id,role,created_by_user_id)
		VALUES ($1,$2,'reader',$3)`, accountID, memberID, initialAdminID); err != nil {
		t.Fatalf("seed searchable membership: %v", err)
	}
	name := "Searchable account " + randID(t)[:8]
	if _, err := st.DB().ExecContext(ctx, `
		UPDATE devradar_tenant SET name=$2,plan='paid',status='suspended' WHERE id=$1`,
		accountID, name); err != nil {
		t.Fatalf("configure searchable account: %v", err)
	}

	assertResult := func(query string) {
		t.Helper()
		rows, total, err := st.AdminListAccounts(ctx, query, 10, 0)
		if err != nil {
			t.Fatalf("list accounts for %q: %v", query, err)
		}
		if total != 1 || len(rows) != 1 {
			t.Fatalf("list accounts for %q = %d rows/%d total, want 1/1", query, len(rows), total)
		}
		got := rows[0]
		if got.Account.ID != accountID || got.Account.Name != name || got.Account.Plan != "paid" ||
			got.Account.Status != "suspended" || got.MemberCount != 2 {
			t.Fatalf("account row = %#v, want configured account with 2 members", got)
		}
		if got.InitialAdminEmail == "" || got.InitialAdminEmail == memberEmail {
			t.Fatalf("initial admin email = %q, want original administrator", got.InitialAdminEmail)
		}
		if got.Account.ID == otherAccountID || got.InitialAdminEmail == userEmailByID(t, st, otherAdminID) {
			t.Fatalf("cross-account identity leaked into row: %#v", got)
		}
	}
	assertResult(strings.ToLower(name))
	assertResult(search)
}

func TestAdminDeleteAccountPreservesMultiAccountUserAndForeignData(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	deleteAccountID, sharedUserID := seedAuditAccount(t, st)
	keepAccountID, keepAdminID := seedAuditAccount(t, st)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_account_member (account_id,user_id,role,created_by_user_id)
		VALUES ($1,$2,'reader',$3)`, keepAccountID, sharedUserID, keepAdminID); err != nil {
		t.Fatalf("seed second membership: %v", err)
	}
	var deleteTokenID, keepTokenID string
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_api_token (tenant_id,name,token_hash)
		VALUES ($1,'delete credential',$2) RETURNING id`, deleteAccountID, randID(t)).Scan(&deleteTokenID); err != nil {
		t.Fatalf("seed deleted account token: %v", err)
	}
	if err := st.DB().QueryRowContext(ctx, `
		INSERT INTO devradar_api_token (tenant_id,name,token_hash)
		VALUES ($1,'keep credential',$2) RETURNING id`, keepAccountID, randID(t)).Scan(&keepTokenID); err != nil {
		t.Fatalf("seed kept account token: %v", err)
	}

	paths, err := st.AdminPrepareAccountDeletion(ctx, deleteAccountID, deletionActor(sharedUserID), randID(t))
	if err != nil || len(paths) != 0 {
		t.Fatalf("prepare account deletion = %q, %v", paths, err)
	}
	if err := st.AdminFinalizeAccountDeletion(ctx, deleteAccountID); err != nil {
		t.Fatalf("finalize account deletion: %v", err)
	}
	if _, err := st.GetAccount(ctx, deleteAccountID); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("deleted account lookup = %v, want ErrNotFound", err)
	}
	if _, err := st.GetUser(ctx, sharedUserID); err != nil {
		t.Fatalf("multi-account user was deleted: %v", err)
	}
	access, err := st.GetAccess(ctx, sharedUserID, keepAccountID)
	if err != nil || access.Membership.Role != account.RoleReader {
		t.Fatalf("kept membership = %#v, %v", access, err)
	}
	assertRowCount(t, st, `SELECT count(*) FROM devradar_account_member WHERE account_id=$1`, 0, deleteAccountID)
	assertRowCount(t, st, `SELECT count(*) FROM devradar_api_token WHERE id=$1`, 0, deleteTokenID)
	assertRowCount(t, st, `SELECT count(*) FROM devradar_api_token WHERE id=$1 AND tenant_id=$2`, 1, keepTokenID, keepAccountID)
	if _, err := st.GetAccount(ctx, keepAccountID); err != nil {
		t.Fatalf("foreign account was changed: %v", err)
	}
	if _, err := st.AdminPrepareAccountDeletion(ctx, deleteAccountID, deletionActor(sharedUserID), randID(t)); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("repeat prepare = %v, want ErrNotFound", err)
	}
	if err := st.AdminFinalizeAccountDeletion(ctx, deleteAccountID); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("repeat finalize = %v, want ErrNotFound", err)
	}
}

func TestAdminDeleteAccountPreservesAuthoritativeIdentityAndSession(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	deleteAccountID, sharedUserID := seedAuditAccount(t, st)
	keepAccountID, keepAdminID := seedAuditAccount(t, st)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_account_member (account_id,user_id,role,created_by_user_id)
		VALUES ($1,$2,'reader',$3)`, keepAccountID, sharedUserID, keepAdminID); err != nil {
		t.Fatalf("seed second membership: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_identity (tenant_id,user_id,provider,subject,email)
		SELECT $1,$2,'github',$3,email FROM devradar_user WHERE id=$2`,
		deleteAccountID, sharedUserID, "delete-account-identity-"+randID(t)); err != nil {
		t.Fatalf("seed authoritative identity: %v", err)
	}
	rawSession, err := st.CreateSession(ctx, sharedUserID, &deleteAccountID, time.Hour)
	if err != nil {
		t.Fatalf("create selected session: %v", err)
	}

	if _, err := st.AdminPrepareAccountDeletion(ctx, deleteAccountID, deletionActor(sharedUserID), randID(t)); err != nil {
		t.Fatalf("prepare account deletion: %v", err)
	}
	if err := st.AdminFinalizeAccountDeletion(ctx, deleteAccountID); err != nil {
		t.Fatalf("finalize account deletion: %v", err)
	}

	assertRowCount(t, st, `
		SELECT count(*) FROM devradar_identity
		WHERE user_id=$1 AND tenant_id IS NULL`, 1, sharedUserID)
	assertRowCount(t, st, `
		SELECT count(*) FROM devradar_session
		WHERE user_id=$1 AND tenant_id IS NULL AND active_account_id IS NULL`, 1, sharedUserID)
	session, err := st.ValidateSession(ctx, rawSession)
	if err != nil || session.User.ID != sharedUserID || session.ActiveAccountID != nil {
		t.Fatalf("preserved session = %#v, %v", session, err)
	}
	if _, err := st.GetAccess(ctx, sharedUserID, keepAccountID); err != nil {
		t.Fatalf("remaining account access: %v", err)
	}
	if err := st.SelectSessionAccount(ctx, rawSession, sharedUserID, keepAccountID); err != nil {
		t.Fatalf("select remaining account: %v", err)
	}
	session, err = st.ValidateSession(ctx, rawSession)
	if err != nil || session.ActiveAccountID == nil || *session.ActiveAccountID != keepAccountID {
		t.Fatalf("reselected session = %#v, %v", session, err)
	}
}

func TestAdminAccountDeletionBatchesAndCommitsExactProgress(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, platformUserID := seedAuditAccount(t, st)
	foreignAccountID, _ := seedAuditAccount(t, st)
	want := make([]postgres.AdminAccountDeletionObject, 0, 102)
	for i := range 102 {
		path := fmt.Sprintf("gs://bucket/%s/%03d", accountID, i)
		want = append(want, postgres.AdminAccountDeletionObject{
			SBOMID: seedAdminDeletionSBOM(t, st, accountID, path, i), ObjectPath: path,
		})
	}
	foreignPath := "gs://bucket/" + foreignAccountID + "/foreign"
	foreignID := seedAdminDeletionSBOM(t, st, foreignAccountID, foreignPath, 200)
	sort.Slice(want, func(i, j int) bool { return want[i].ObjectPath < want[j].ObjectPath })

	got, err := st.AdminPrepareAccountDeletion(ctx, accountID, deletionActor(platformUserID), randID(t))
	if err != nil {
		t.Fatalf("prepare account deletion: %v", err)
	}
	if !slices.Equal(got, want[:100]) {
		t.Fatalf("first deletion batch = %#v, want first 100 deterministic objects", got)
	}
	account, err := st.GetAccount(ctx, accountID)
	if err != nil || account.Status != "suspended" {
		t.Fatalf("prepared account = %#v, %v, want suspended", account, err)
	}
	for _, object := range got {
		if err := st.AdminDeleteAccountSBOM(ctx, accountID, object.SBOMID); err != nil {
			t.Fatalf("commit deletion progress for %s: %v", object.SBOMID, err)
		}
	}
	assertRowCount(t, st, `SELECT count(*) FROM devradar_sbom WHERE tenant_id=$1`, 2, accountID)
	assertRowCount(t, st, `SELECT count(*) FROM devradar_sbom WHERE tenant_id=$1 AND id=$2`, 1, foreignAccountID, foreignID)

	retry, err := st.AdminPrepareAccountDeletion(ctx, accountID, deletionActor(platformUserID), randID(t))
	if err != nil || !slices.Equal(retry, want[100:]) {
		t.Fatalf("retry batch = %#v, %v, want final two objects", retry, err)
	}
	if err := st.AdminDeleteAccountSBOM(ctx, foreignAccountID, retry[0].SBOMID); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("foreign-account row deletion = %v, want ErrNotFound", err)
	}
}

func TestAdminAccountDeletionPendingGraceAndFinalizeGuard(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, platformUserID := seedAuditAccount(t, st)
	stalePath := "gs://bucket/" + accountID + "/stale-pending"
	youngPath := "gs://bucket/" + accountID + "/young-pending"
	staleID := seedAdminDeletionSBOM(t, st, accountID, stalePath, 1)
	youngID := seedAdminDeletionSBOM(t, st, accountID, youngPath, 2)
	if _, err := st.DB().ExecContext(ctx, `
		UPDATE devradar_sbom
		SET status='pending',submitted_at=CASE id WHEN $1 THEN now()-interval '10 minutes' ELSE now() END
		WHERE id IN ($1,$2)`, staleID, youngID); err != nil {
		t.Fatalf("configure pending rows: %v", err)
	}

	batch, err := st.AdminPrepareAccountDeletion(ctx, accountID, deletionActor(platformUserID), randID(t))
	if err != nil {
		t.Fatalf("prepare pending deletion: %v", err)
	}
	want := []postgres.AdminAccountDeletionObject{{SBOMID: staleID, ObjectPath: stalePath}}
	if !slices.Equal(batch, want) {
		t.Fatalf("pending deletion batch = %#v, want stale row only", batch)
	}
	if err := st.AdminDeleteAccountSBOM(ctx, accountID, staleID); err != nil {
		t.Fatalf("delete stale pending row: %v", err)
	}
	if err := st.AdminFinalizeAccountDeletion(ctx, accountID); !errors.Is(err, postgres.ErrAccountDeletionIncomplete) {
		t.Fatalf("finalize with young pending row = %v, want ErrAccountDeletionIncomplete", err)
	}
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_sbom SET submitted_at=now()-interval '10 minutes' WHERE id=$1`, youngID); err != nil {
		t.Fatalf("age pending row: %v", err)
	}
	retry, err := st.AdminPrepareAccountDeletion(ctx, accountID, deletionActor(platformUserID), randID(t))
	if err != nil || !slices.Equal(retry, []postgres.AdminAccountDeletionObject{{SBOMID: youngID, ObjectPath: youngPath}}) {
		t.Fatalf("stale pending retry = %#v, %v", retry, err)
	}
}

func TestAdminAccountDeletionFinalizeRequiresSuspendedEmptyAccount(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, platformUserID := seedAuditAccount(t, st)
	if err := st.AdminFinalizeAccountDeletion(ctx, accountID); !errors.Is(err, postgres.ErrAccountDeletionIncomplete) {
		t.Fatalf("finalize active account = %v, want ErrAccountDeletionIncomplete", err)
	}
	id := seedAdminDeletionSBOM(t, st, accountID, "gs://bucket/"+accountID+"/guard", 1)
	if _, err := st.AdminPrepareAccountDeletion(ctx, accountID, deletionActor(platformUserID), randID(t)); err != nil {
		t.Fatalf("prepare guarded deletion: %v", err)
	}
	if err := st.AdminFinalizeAccountDeletion(ctx, accountID); !errors.Is(err, postgres.ErrAccountDeletionIncomplete) {
		t.Fatalf("finalize non-empty account = %v, want ErrAccountDeletionIncomplete", err)
	}
	if err := st.AdminDeleteAccountSBOM(ctx, accountID, id); err != nil {
		t.Fatalf("delete guarded SBOM: %v", err)
	}
	if err := st.AdminFinalizeAccountDeletion(ctx, accountID); err != nil {
		t.Fatalf("finalize suspended empty account: %v", err)
	}
}

func TestAdminDeleteAccountSBOMPreservesRowOnCancellationAndDatabaseFailure(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, platformUserID := seedAuditAccount(t, st)
	id := seedAdminDeletionSBOM(t, st, accountID, "gs://bucket/"+accountID+"/blocked", 1)
	if _, err := st.AdminPrepareAccountDeletion(ctx, accountID, deletionActor(platformUserID), randID(t)); err != nil {
		t.Fatalf("prepare blocked deletion: %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := st.AdminDeleteAccountSBOM(canceled, accountID, id); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled row deletion = %v, want context.Canceled", err)
	}
	assertRowCount(t, st, `SELECT count(*) FROM devradar_sbom WHERE tenant_id=$1 AND id=$2`, 1, accountID, id)

	blocker := "test_account_sbom_block_" + randID(t)
	if _, err := st.DB().ExecContext(ctx, `CREATE TABLE `+blocker+` (
		sbom_id TEXT PRIMARY KEY REFERENCES devradar_sbom(id) ON DELETE RESTRICT)`); err != nil {
		t.Fatalf("create SBOM deletion blocker: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `INSERT INTO `+blocker+` (sbom_id) VALUES ($1)`, id); err != nil {
		t.Fatalf("seed SBOM deletion blocker: %v", err)
	}
	if err := st.AdminDeleteAccountSBOM(ctx, accountID, id); err == nil {
		t.Fatal("database-blocked row deletion returned nil")
	}
	assertRowCount(t, st, `SELECT count(*) FROM devradar_sbom WHERE tenant_id=$1 AND id=$2`, 1, accountID, id)
	if _, err := st.DB().ExecContext(ctx, `DROP TABLE `+blocker); err != nil {
		t.Fatalf("drop SBOM deletion blocker: %v", err)
	}
	if err := st.AdminDeleteAccountSBOM(ctx, accountID, id); err != nil {
		t.Fatalf("retry row deletion: %v", err)
	}
}

func TestAdminAccountDeletionMarkerIsUniqueAttributedAndBlocksStatusChanges(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, platformUserID := seedAuditAccount(t, st)
	requestID := randID(t)
	if _, err := st.AdminPrepareAccountDeletion(ctx, accountID, deletionActor(platformUserID), requestID); err != nil {
		t.Fatalf("first deletion preparation: %v", err)
	}
	accountAfterFirst, err := st.GetAccount(ctx, accountID)
	if err != nil {
		t.Fatalf("read first prepared account: %v", err)
	}
	var markerCount int
	var actorKind, actorUserID, action, targetType, targetID, outcome, gotRequestID string
	if err := st.DB().QueryRowContext(ctx, `
		SELECT count(*),min(actor_kind),min(actor_user_id::text),min(action),min(target_type),
		       min(target_id),min(outcome),min(request_id)
		FROM devradar_audit_event
		WHERE account_id=$1 AND action='account.delete.start'`, accountID).
		Scan(&markerCount, &actorKind, &actorUserID, &action, &targetType, &targetID, &outcome, &gotRequestID); err != nil {
		t.Fatalf("read deletion marker: %v", err)
	}
	if markerCount != 1 || actorKind != string(account.ActorPlatform) || actorUserID != platformUserID ||
		action != "account.delete.start" || targetType != "account" || targetID != accountID ||
		outcome != "success" || gotRequestID != requestID {
		t.Fatalf("deletion marker = count:%d actor:%s/%s event:%s/%s/%s/%s request:%s",
			markerCount, actorKind, actorUserID, action, targetType, targetID, outcome, gotRequestID)
	}
	if _, err := st.AdminPrepareAccountDeletion(ctx, accountID, deletionActor(platformUserID), randID(t)); err != nil {
		t.Fatalf("repeat deletion preparation: %v", err)
	}
	accountAfterRetry, err := st.GetAccount(ctx, accountID)
	if err != nil {
		t.Fatalf("read retried prepared account: %v", err)
	}
	if !accountAfterRetry.UpdatedAt.Equal(accountAfterFirst.UpdatedAt) {
		t.Fatalf("suspension timestamp changed: first=%s retry=%s", accountAfterFirst.UpdatedAt, accountAfterRetry.UpdatedAt)
	}
	assertRowCount(t, st, `SELECT count(*) FROM devradar_audit_event WHERE account_id=$1 AND action='account.delete.start'`, 1, accountID)
	for _, status := range []string{"active", "suspended"} {
		if err := st.AdminSetAccountStatus(ctx, accountID, status); !errors.Is(err, postgres.ErrAccountDeletionInProgress) {
			t.Fatalf("set deletion-started account status %q = %v, want ErrAccountDeletionInProgress", status, err)
		}
	}

	ordinaryID, _ := seedAuditAccount(t, st)
	if err := st.AdminSetAccountStatus(ctx, ordinaryID, "suspended"); err != nil {
		t.Fatalf("suspend ordinary account: %v", err)
	}
	if err := st.AdminSetAccountStatus(ctx, ordinaryID, "active"); err != nil {
		t.Fatalf("reactivate ordinary suspended account: %v", err)
	}
}

func TestAdminFinalizeAccountDeletionRequiresDurableMarker(t *testing.T) {
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	accountID, platformUserID := seedAuditAccount(t, st)
	if err := st.AdminSetAccountStatus(ctx, accountID, "suspended"); err != nil {
		t.Fatalf("suspend unmarked account: %v", err)
	}
	if err := st.AdminFinalizeAccountDeletion(ctx, accountID); !errors.Is(err, postgres.ErrAccountDeletionIncomplete) {
		t.Fatalf("finalize unmarked suspended account = %v, want ErrAccountDeletionIncomplete", err)
	}
	if _, err := st.AdminPrepareAccountDeletion(ctx, accountID, deletionActor(platformUserID), randID(t)); err != nil {
		t.Fatalf("mark account deletion: %v", err)
	}
	if err := st.AdminFinalizeAccountDeletion(ctx, accountID); err != nil {
		t.Fatalf("finalize marked empty account: %v", err)
	}
}

func seedAdminDeletionSBOM(t *testing.T, st *postgres.Store, accountID, objectPath string, index int) string {
	t.Helper()
	id := randID(t)
	if _, err := st.DB().ExecContext(context.Background(), `
		INSERT INTO devradar_sbom
			(id,tenant_id,image_ref,repository,digest,format,object_path,status,submitted_at)
		VALUES ($1,$2,$3,$3,$4,'cyclonedx',$5,'active',TIMESTAMPTZ '2026-01-01 00:00:00+00' + $6 * interval '1 second')`,
		id, accountID, "registry.example/delete-"+id, fmt.Sprintf("sha256:%064d", index+1), objectPath, index); err != nil {
		t.Fatalf("seed deletion SBOM: %v", err)
	}
	return id
}

func userEmailByID(t *testing.T, st *postgres.Store, userID string) string {
	t.Helper()
	user, err := st.GetUser(context.Background(), userID)
	if err != nil {
		t.Fatalf("get user %s: %v", userID, err)
	}
	return user.Email
}

func assertRowCount(t *testing.T, st *postgres.Store, query string, want int, args ...any) {
	t.Helper()
	var got int
	if err := st.DB().QueryRowContext(context.Background(), query, args...).Scan(&got); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if got != want {
		t.Fatalf("row count = %d, want %d", got, want)
	}
}

func deletionActor(userID string) account.Actor {
	return account.Actor{Kind: account.ActorPlatform, UserID: userID}
}

package server_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/lib/pq"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/server"
)

type accountDeletionBlob struct {
	store             *postgres.Store
	accountID         string
	wantRowsDuringIO  int
	objects           map[string][]byte
	deleted           []string
	failPath          string
	failErr           error
	observationErrors []error
}

func (b *accountDeletionBlob) Put(_ context.Context, objectPath string, data []byte) error {
	b.objects[objectPath] = slices.Clone(data)
	return nil
}

func (b *accountDeletionBlob) Delete(ctx context.Context, objectPath string) error {
	var status string
	if err := b.store.DB().QueryRowContext(ctx,
		`SELECT status FROM devradar_tenant WHERE id=$1`, b.accountID).Scan(&status); err != nil {
		b.observationErrors = append(b.observationErrors, fmt.Errorf("account missing during blob delete: %w", err))
	} else if status != "suspended" {
		b.observationErrors = append(b.observationErrors, fmt.Errorf("account status during blob delete = %q", status))
	}
	var rows int
	if err := b.store.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_sbom WHERE tenant_id=$1`, b.accountID).Scan(&rows); err != nil {
		b.observationErrors = append(b.observationErrors, fmt.Errorf("read paths during blob delete: %w", err))
	} else if rows != b.wantRowsDuringIO {
		b.observationErrors = append(b.observationErrors,
			fmt.Errorf("SBOM rows during blob delete = %d, want %d", rows, b.wantRowsDuringIO))
	}
	b.deleted = append(b.deleted, objectPath)
	if objectPath == b.failPath {
		return b.failErr
	}
	delete(b.objects, objectPath)
	if b.wantRowsDuringIO > 0 {
		b.wantRowsDuringIO--
	}
	return nil
}

func TestAdminDeleteAccountCleansExactBlobsBeforeDatabaseFinalize(t *testing.T) {
	srv, st, blob, session, accountID, foreignAccountID, paths, foreignPath := setupAdminAccountDeletion(t)
	rec := postAdminAccountDelete(t, srv.Handler(), session, accountID)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/accounts?msg=account_deleted" {
		t.Fatalf("delete account = %d %q: %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if len(blob.observationErrors) != 0 {
		t.Fatalf("blob deletion ordering errors = %v", blob.observationErrors)
	}
	if !slices.Equal(blob.deleted, paths) {
		t.Fatalf("deleted paths = %q, want %q", blob.deleted, paths)
	}
	for _, path := range paths {
		if _, ok := blob.objects[path]; ok {
			t.Fatalf("target blob %q remains", path)
		}
	}
	if _, ok := blob.objects[foreignPath]; !ok {
		t.Fatalf("foreign blob %q was deleted", foreignPath)
	}
	if _, err := st.GetAccount(context.Background(), accountID); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("finalized account lookup = %v, want ErrNotFound", err)
	}
	if _, err := st.GetAccount(context.Background(), foreignAccountID); err != nil {
		t.Fatalf("foreign account changed: %v", err)
	}
}

func TestAdminDeleteAccountBlobFailurePreservesPathsAndRetryCompletes(t *testing.T) {
	srv, st, blob, session, accountID, _, paths, foreignPath := setupAdminAccountDeletion(t)
	blob.failPath = paths[1]
	blob.failErr = errors.New("transient blob delete")
	rec := postAdminAccountDelete(t, srv.Handler(), session, accountID)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/account/"+accountID+"?msg=cleanup_failed" {
		t.Fatalf("failed delete = %d %q: %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	account, err := st.GetAccount(context.Background(), accountID)
	if err != nil || account.Status != "suspended" {
		t.Fatalf("failed deletion account = %#v, %v, want suspended", account, err)
	}
	assertServerRowCount(t, st, `SELECT count(*) FROM devradar_sbom WHERE tenant_id=$1`, 1, accountID)
	if _, ok := blob.objects[paths[0]]; ok {
		t.Fatalf("first blob %q should have been deleted before partial failure", paths[0])
	}
	if _, ok := blob.objects[paths[1]]; !ok {
		t.Fatalf("failed blob %q should remain", paths[1])
	}
	if _, ok := blob.objects[foreignPath]; !ok {
		t.Fatal("foreign blob changed during partial failure")
	}

	blob.failPath = ""
	blob.failErr = nil
	retry := postAdminAccountDelete(t, srv.Handler(), session, accountID)
	if retry.Code != http.StatusSeeOther || retry.Header().Get("Location") != "/admin/accounts?msg=account_deleted" {
		t.Fatalf("retry delete = %d %q: %s", retry.Code, retry.Header().Get("Location"), retry.Body.String())
	}
	if _, err := st.GetAccount(context.Background(), accountID); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("retry account lookup = %v, want ErrNotFound", err)
	}
	if _, ok := blob.objects[foreignPath]; !ok {
		t.Fatal("foreign blob changed during retry")
	}
}

func TestAdminDeleteAccountFinalizeFailureStaysSuspendedAndRetryCompletes(t *testing.T) {
	srv, st, blob, session, accountID, _, paths, _ := setupAdminAccountDeletion(t)
	table := pq.QuoteIdentifier("test_account_delete_block_" + randomHex(t, 6))
	if _, err := st.DB().ExecContext(context.Background(), `
		CREATE TABLE `+table+` (
			account_id UUID PRIMARY KEY REFERENCES devradar_tenant(id) ON DELETE RESTRICT
		)`); err != nil {
		t.Fatalf("create deletion blocker: %v", err)
	}
	t.Cleanup(func() { _, _ = st.DB().ExecContext(context.Background(), `DROP TABLE IF EXISTS `+table) })
	if _, err := st.DB().ExecContext(context.Background(),
		`INSERT INTO `+table+` (account_id) VALUES ($1)`, accountID); err != nil {
		t.Fatalf("insert deletion blocker: %v", err)
	}

	rec := postAdminAccountDelete(t, srv.Handler(), session, accountID)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/account/"+accountID+"?msg=cleanup_failed" {
		t.Fatalf("blocked finalize = %d %q: %s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	account, err := st.GetAccount(context.Background(), accountID)
	if err != nil || account.Status != "suspended" {
		t.Fatalf("blocked finalize account = %#v, %v, want suspended", account, err)
	}
	assertServerRowCount(t, st, `SELECT count(*) FROM devradar_sbom WHERE tenant_id=$1`, 0, accountID)
	for _, path := range paths {
		if _, ok := blob.objects[path]; ok {
			t.Fatalf("blob %q remains after DB finalize failure", path)
		}
	}
	if _, err := st.DB().ExecContext(context.Background(), `DROP TABLE `+table); err != nil {
		t.Fatalf("drop deletion blocker: %v", err)
	}
	retry := postAdminAccountDelete(t, srv.Handler(), session, accountID)
	if retry.Code != http.StatusSeeOther || retry.Header().Get("Location") != "/admin/accounts?msg=account_deleted" {
		t.Fatalf("finalize retry = %d %q: %s", retry.Code, retry.Header().Get("Location"), retry.Body.String())
	}
}

func TestAdminDeleteAccountUsesBoundedBatchesAndReportsProgress(t *testing.T) {
	srv, st, blob, session, accountID, _, paths, _ := setupAdminAccountDeletion(t)
	for i := 2; i < 101; i++ {
		path := fmt.Sprintf("gs://test-bucket/%s/%03d", accountID, i)
		seedServerDeletionSBOM(t, st, accountID, path, i)
		blob.objects[path] = []byte(path)
		paths = append(paths, path)
	}
	blob.wantRowsDuringIO = len(paths)

	first := postAdminAccountDelete(t, srv.Handler(), session, accountID)
	if first.Code != http.StatusSeeOther || first.Header().Get("Location") != "/admin/account/"+accountID+"?msg=cleanup_in_progress" {
		t.Fatalf("first deletion batch = %d %q: %s", first.Code, first.Header().Get("Location"), first.Body.String())
	}
	assertServerRowCount(t, st, `SELECT count(*) FROM devradar_sbom WHERE tenant_id=$1`, 1, accountID)
	if len(blob.deleted) != 100 {
		t.Fatalf("first deletion batch deleted %d blobs, want 100", len(blob.deleted))
	}

	second := postAdminAccountDelete(t, srv.Handler(), session, accountID)
	if second.Code != http.StatusSeeOther || second.Header().Get("Location") != "/admin/accounts?msg=account_deleted" {
		t.Fatalf("second deletion batch = %d %q: %s", second.Code, second.Header().Get("Location"), second.Body.String())
	}
	if len(blob.deleted) != 101 {
		t.Fatalf("converged deletion deleted %d blobs, want 101", len(blob.deleted))
	}
}

func TestAdminDeleteAccountYoungPendingReportsProgressUntilStale(t *testing.T) {
	srv, st, blob, session, accountID, _, paths, _ := setupAdminAccountDeletion(t)
	if _, err := st.DB().ExecContext(context.Background(),
		`UPDATE devradar_sbom SET status='pending',submitted_at=now() WHERE object_path=$1`, paths[0]); err != nil {
		t.Fatalf("make pending SBOM young: %v", err)
	}

	first := postAdminAccountDelete(t, srv.Handler(), session, accountID)
	if first.Code != http.StatusSeeOther || first.Header().Get("Location") != "/admin/account/"+accountID+"?msg=cleanup_in_progress" {
		t.Fatalf("young pending deletion = %d %q: %s", first.Code, first.Header().Get("Location"), first.Body.String())
	}
	if _, ok := blob.objects[paths[0]]; !ok {
		t.Fatal("young pending blob was deleted before grace")
	}
	assertServerRowCount(t, st, `SELECT count(*) FROM devradar_sbom WHERE tenant_id=$1`, 1, accountID)
	if _, err := st.DB().ExecContext(context.Background(),
		`UPDATE devradar_sbom SET submitted_at=now()-interval '10 minutes' WHERE object_path=$1`, paths[0]); err != nil {
		t.Fatalf("age pending SBOM: %v", err)
	}
	blob.wantRowsDuringIO = 1

	retry := postAdminAccountDelete(t, srv.Handler(), session, accountID)
	if retry.Code != http.StatusSeeOther || retry.Header().Get("Location") != "/admin/accounts?msg=account_deleted" {
		t.Fatalf("stale pending retry = %d %q: %s", retry.Code, retry.Header().Get("Location"), retry.Body.String())
	}
}

func TestAdminDeleteAccountRowFailurePreservesRetryableProgress(t *testing.T) {
	srv, st, blob, session, accountID, _, paths, _ := setupAdminAccountDeletion(t)
	blocker := pq.QuoteIdentifier("test_account_sbom_delete_block_" + randomHex(t, 6))
	if _, err := st.DB().ExecContext(context.Background(), `CREATE TABLE `+blocker+` (
		sbom_id TEXT PRIMARY KEY REFERENCES devradar_sbom(id) ON DELETE RESTRICT)`); err != nil {
		t.Fatalf("create SBOM row blocker: %v", err)
	}
	var blockedID string
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT id FROM devradar_sbom WHERE tenant_id=$1 AND object_path=$2`, accountID, paths[0]).Scan(&blockedID); err != nil {
		t.Fatalf("read blocked SBOM id: %v", err)
	}
	if _, err := st.DB().ExecContext(context.Background(),
		`UPDATE devradar_sbom SET submitted_at=now()-interval '1 hour' WHERE id=$1`, blockedID); err != nil {
		t.Fatalf("order blocked SBOM first: %v", err)
	}
	if _, err := st.DB().ExecContext(context.Background(), `INSERT INTO `+blocker+` (sbom_id) VALUES ($1)`, blockedID); err != nil {
		t.Fatalf("seed SBOM row blocker: %v", err)
	}

	first := postAdminAccountDelete(t, srv.Handler(), session, accountID)
	if first.Code != http.StatusSeeOther || first.Header().Get("Location") != "/admin/account/"+accountID+"?msg=cleanup_failed" {
		t.Fatalf("blocked row deletion = %d %q: %s", first.Code, first.Header().Get("Location"), first.Body.String())
	}
	assertServerRowCount(t, st, `SELECT count(*) FROM devradar_sbom WHERE tenant_id=$1`, len(paths), accountID)
	if _, ok := blob.objects[paths[0]]; ok {
		t.Fatal("blob should be gone before durable row-delete failure")
	}
	if _, err := st.DB().ExecContext(context.Background(), `DROP TABLE `+blocker); err != nil {
		t.Fatalf("drop SBOM row blocker: %v", err)
	}
	blob.wantRowsDuringIO = len(paths)

	retry := postAdminAccountDelete(t, srv.Handler(), session, accountID)
	if retry.Code != http.StatusSeeOther || retry.Header().Get("Location") != "/admin/accounts?msg=account_deleted" {
		t.Fatalf("blocked row retry = %d %q: %s", retry.Code, retry.Header().Get("Location"), retry.Body.String())
	}
}

func TestAdminDeleteAccountMarkerBlocksStatusRouteReactivation(t *testing.T) {
	srv, st, blob, session, accountID, _, paths, _ := setupAdminAccountDeletion(t)
	blob.failPath = paths[0]
	blob.failErr = errors.New("leave deletion in progress")
	started := postAdminAccountDelete(t, srv.Handler(), session, accountID)
	if started.Code != http.StatusSeeOther || started.Header().Get("Location") != "/admin/account/"+accountID+"?msg=cleanup_failed" {
		t.Fatalf("start deletion = %d %q: %s", started.Code, started.Header().Get("Location"), started.Body.String())
	}

	reactivate := postAdminAccountStatus(t, srv.Handler(), session, accountID, "active")
	if reactivate.Code != http.StatusSeeOther || reactivate.Header().Get("Location") != "/admin/account/"+accountID+"?msg=deletion_in_progress" {
		t.Fatalf("reactivate deleting account = %d %q: %s", reactivate.Code, reactivate.Header().Get("Location"), reactivate.Body.String())
	}
	accountRow, err := st.GetAccount(context.Background(), accountID)
	if err != nil || accountRow.Status != "suspended" {
		t.Fatalf("deletion-started account after reactivation = %#v, %v", accountRow, err)
	}
}

func setupAdminAccountDeletion(
	t *testing.T,
) (*server.Server, *postgres.Store, *accountDeletionBlob, *http.Cookie, string, string, []string, string) {
	t.Helper()
	st := testPostgresStore(t)
	adminAccountID, _ := seedTenantToken(t, st)
	t.Setenv("DEVRADAR_ADMIN_USERS", platformActorEmail(t, st, adminAccountID))
	session := seedSession(t, st, adminAccountID)
	accountID, _ := seedTenantToken(t, st)
	seedLegacyUser(t, st, accountID)
	foreignAccountID, _ := seedTenantToken(t, st)
	paths := []string{
		"gs://test-bucket/" + accountID + "/one",
		"gs://test-bucket/" + accountID + "/two",
	}
	for i, path := range paths {
		seedServerDeletionSBOM(t, st, accountID, path, i)
	}
	foreignPath := "gs://test-bucket/" + foreignAccountID + "/foreign"
	seedServerDeletionSBOM(t, st, foreignAccountID, foreignPath, 3)
	blob := &accountDeletionBlob{
		store: st, accountID: accountID, wantRowsDuringIO: len(paths),
		objects: map[string][]byte{
			paths[0]: []byte("one"), paths[1]: []byte("two"), foreignPath: []byte("foreign"),
		},
	}
	srv := server.New(st, blob, nil, nil, nil, server.Options{Version: "test"})
	return srv, st, blob, session, accountID, foreignAccountID, paths, foreignPath
}

func seedServerDeletionSBOM(t *testing.T, st *postgres.Store, accountID, objectPath string, index int) {
	t.Helper()
	id := randomHex(t, 16)
	if _, err := st.DB().ExecContext(context.Background(), `
		INSERT INTO devradar_sbom
			(id,tenant_id,image_ref,repository,digest,format,object_path,status)
		VALUES ($1,$2,$3,$3,$4,'cyclonedx',$5,'active')`,
		id, accountID, "registry.example/delete-"+id, fmt.Sprintf("sha256:%064d", index+1), objectPath); err != nil {
		t.Fatalf("seed deletion SBOM: %v", err)
	}
}

func postAdminAccountDelete(
	t *testing.T,
	h http.Handler,
	session *http.Cookie,
	accountID string,
) *httptest.ResponseRecorder {
	t.Helper()
	csrfCookie, csrfToken := csrfFor(t, h, session, "/admin/account/"+accountID)
	req := httptest.NewRequest(http.MethodPost, "/admin/account/"+accountID+"/delete",
		strings.NewReader(url.Values{"csrf_token": {csrfToken}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	req.AddCookie(csrfCookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func postAdminAccountStatus(
	t *testing.T,
	h http.Handler,
	session *http.Cookie,
	accountID, status string,
) *httptest.ResponseRecorder {
	t.Helper()
	path := "/admin/account/" + accountID
	csrfCookie, csrfToken := csrfFor(t, h, session, path)
	req := httptest.NewRequest(http.MethodPost, path+"/status", strings.NewReader(url.Values{
		"csrf_token": {csrfToken}, "status": {status},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(session)
	req.AddCookie(csrfCookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func assertServerRowCount(t *testing.T, st *postgres.Store, query string, want int, args ...any) {
	t.Helper()
	var got int
	if err := st.DB().QueryRowContext(context.Background(), query, args...).Scan(&got); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if got != want {
		t.Fatalf("row count = %d, want %d", got, want)
	}
}

var _ server.BlobStore = (*accountDeletionBlob)(nil)

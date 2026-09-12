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
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/attest"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/gcs"
	"github.com/thingzio/devradar/pkg/server"
)

// flakyBlob is a BlobStore whose Put fails until failN calls have been made,
// then succeeds — modeling a transient object-storage outage so we can assert
// the pending→active lifecycle self-heals on retry.
type flakyBlob struct {
	inner  gcs.Store
	fail   bool
	failN  int
	calls  int
	putErr error
}

type blockingBlob struct {
	inner      gcs.Store
	putStarted chan string
	releasePut chan struct{}
	deleteErr  error
	deleted    []string
}

func (b *blockingBlob) Put(ctx context.Context, objectPath string, data []byte) error {
	if err := b.inner.Put(ctx, objectPath, data); err != nil {
		return err
	}
	b.putStarted <- objectPath
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.releasePut:
		return nil
	}
}

func (b *blockingBlob) Delete(ctx context.Context, objectPath string) error {
	b.deleted = append(b.deleted, objectPath)
	if b.deleteErr != nil {
		return b.deleteErr
	}
	return b.inner.Delete(ctx, objectPath)
}

func (b *flakyBlob) Put(ctx context.Context, objectPath string, data []byte) error {
	b.calls++
	if b.fail && b.calls <= b.failN {
		return b.putErr
	}
	return b.inner.Put(ctx, objectPath, data)
}

func (b *flakyBlob) Delete(ctx context.Context, objectPath string) error {
	return b.inner.Delete(ctx, objectPath)
}

// sbomStatus reads the raw status column for one SBOM id (empty if the row is
// absent — e.g. a cleaned-up pending row).
func sbomStatus(t *testing.T, st *postgres.Store, id string) string {
	t.Helper()
	var status string
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT status FROM devradar_sbom WHERE id=$1`, id).Scan(&status); err != nil {
		return "" // no row (e.g. a cleaned-up pending row)
	}
	return status
}

// serverWithBlob builds a Server with a caller-supplied blob store so a test can
// inject storage failures. Mirrors testServer's DB skip behavior.
func serverWithBlob(t *testing.T, blobs server.BlobStore) (*server.Server, *postgres.Store) {
	t.Helper()
	st := testPostgresStore(t)
	return server.New(st, blobs, nil, nil, nil, server.Options{Version: "test"}), st
}

// serverWithVerifier builds a Server with an injected attestation verifier (and a
// local blob store) so ingest tests can exercise the verified/failed/error paths
// without real cryptography.
func serverWithVerifier(t *testing.T, v attest.Verifier) (*server.Server, *postgres.Store) {
	t.Helper()
	st := testPostgresStore(t)
	return server.New(st, gcs.LocalStore{Dir: t.TempDir()}, nil, nil, v, server.Options{Version: "test"}), st
}

func submitBody(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../sbom/testdata/redis.syft.cdx.json")
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	body, _ := json.Marshal(map[string]string{"sbom": base64.StdEncoding.EncodeToString(raw)})
	return string(body)
}

// TestIngest_LifecycleActivatesOnSuccess: a normal submission stores bytes and
// ends with the row 'active' (visible to scan + read).
func TestIngest_LifecycleActivatesOnSuccess(t *testing.T) {
	blob := &flakyBlob{inner: gcs.LocalStore{Dir: t.TempDir()}}
	srv, st := serverWithBlob(t, blob)
	_, tok := seedTenantToken(t, st)
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodPost, "/v1/sboms", strings.NewReader(submitBody(t)))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("submit = %d, want 202: %s", rec.Code, rec.Body.String())
	}
	var sub struct {
		SBOMID string `json:"sbom_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &sub)

	if got := sbomStatus(t, st, sub.SBOMID); got != "active" {
		t.Errorf("status = %q, want active", got)
	}
	if blob.calls != 1 {
		t.Errorf("Put calls = %d, want 1", blob.calls)
	}
}

// TestIngest_LifecycleBlobFailureNoActiveRow: if storing the bytes fails, the
// submission returns 500 and leaves NO active row — the pending row is cleaned
// up, so nothing unscannable is stranded.
func TestIngest_LifecycleBlobFailureNoActiveRow(t *testing.T) {
	blob := &flakyBlob{inner: gcs.LocalStore{Dir: t.TempDir()}, fail: true, failN: 1000, putErr: errors.New("gcs down")}
	srv, st := serverWithBlob(t, blob)
	tenantID, tok := seedTenantToken(t, st)
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodPost, "/v1/sboms", strings.NewReader(submitBody(t)))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("submit with failing blob = %d, want 500", rec.Code)
	}

	// No row of any status remains for this tenant — the pending row was cleaned
	// up, so nothing unscannable is stranded.
	var rows int
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM devradar_sbom WHERE tenant_id=$1`, tenantID).Scan(&rows); err != nil {
		t.Fatalf("count tenant rows: %v", err)
	}
	if rows != 0 {
		t.Errorf("expected no stranded row after blob failure, found %d", rows)
	}
}

// TestIngest_LifecycleSelfHealsOnRetry: a transient blob failure leaves nothing
// active; a retry (blob now healthy) succeeds and produces exactly one active
// row. Verifies the self-heal path (pending row re-driven on resubmit).
func TestIngest_LifecycleSelfHealsOnRetry(t *testing.T) {
	// First Put fails, subsequent succeed.
	blob := &flakyBlob{inner: gcs.LocalStore{Dir: t.TempDir()}, fail: true, failN: 1, putErr: errors.New("transient")}
	srv, st := serverWithBlob(t, blob)
	_, tok := seedTenantToken(t, st)
	h := srv.Handler()
	body := submitBody(t)

	do := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/sboms", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rc := do(); rc.Code != http.StatusInternalServerError {
		t.Fatalf("first submit = %d, want 500", rc.Code)
	}
	rc := do()
	if rc.Code != http.StatusAccepted {
		t.Fatalf("retry submit = %d, want 202: %s", rc.Code, rc.Body.String())
	}
	var sub struct {
		SBOMID string `json:"sbom_id"`
	}
	_ = json.Unmarshal(rc.Body.Bytes(), &sub)
	if got := sbomStatus(t, st, sub.SBOMID); got != "active" {
		t.Errorf("after retry status = %q, want active", got)
	}
	// Exactly one row for this SBOM id.
	var rows int
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM devradar_sbom WHERE id=$1`, sub.SBOMID).Scan(&rows); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rows != 1 {
		t.Errorf("want exactly 1 row, got %d", rows)
	}
}

func TestIngestSuspensionAfterPendingPutCompensatesBlobAndRow(t *testing.T) {
	local := gcs.LocalStore{Dir: t.TempDir()}
	blob := &blockingBlob{
		inner: local, putStarted: make(chan string, 1), releasePut: make(chan struct{}),
	}
	srv, st := serverWithBlob(t, blob)
	accountID, token := seedTenantToken(t, st)
	result := submitSBOMAsync(srv.Handler(), token, submitBody(t))

	objectPath := <-blob.putStarted
	var sbomID, status string
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT id,status FROM devradar_sbom WHERE tenant_id=$1 AND object_path=$2`, accountID, objectPath).
		Scan(&sbomID, &status); err != nil {
		t.Fatalf("read pending ingest: %v", err)
	}
	if status != "pending" {
		t.Fatalf("blocked ingest status = %q, want pending", status)
	}
	objects, err := st.AdminPrepareAccountDeletion(context.Background(), accountID,
		account.Actor{Kind: account.ActorPlatform}, randomHex(t, 8))
	if err != nil {
		t.Fatalf("suspend account during Put: %v", err)
	}
	if len(objects) != 0 {
		t.Fatalf("young pending cleanup batch = %#v, want empty", objects)
	}
	close(blob.releasePut)
	rec := <-result
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("submit after suspension = %d, want 500: %s", rec.Code, rec.Body.String())
	}
	if got := sbomStatus(t, st, sbomID); got != "" {
		t.Fatalf("compensated SBOM status = %q, want deleted row", got)
	}
	if len(blob.deleted) != 1 || blob.deleted[0] != objectPath {
		t.Fatalf("compensating blob deletes = %q, want exact path %q", blob.deleted, objectPath)
	}
	if _, err := local.Fetch(context.Background(), objectPath); err == nil {
		t.Fatal("compensated blob remains readable")
	}
}

func TestIngestSuspensionBeforeUpsertRejectsWithoutBlobWrite(t *testing.T) {
	local := gcs.LocalStore{Dir: t.TempDir()}
	blob := &blockingBlob{
		inner: local, putStarted: make(chan string, 1), releasePut: make(chan struct{}),
	}
	srv, st := serverWithBlob(t, blob)
	accountID, token := seedTenantToken(t, st)
	ctx := context.Background()
	tx, err := st.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin suspension transaction: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	var lockerPID int
	if err := tx.QueryRowContext(ctx, `
		SELECT pg_backend_pid() FROM devradar_tenant WHERE id=$1 FOR NO KEY UPDATE`, accountID).Scan(&lockerPID); err != nil {
		t.Fatalf("lock account before ingest: %v", err)
	}
	result := submitSBOMAsync(srv.Handler(), token, submitBody(t))
	waitForBlockedAccountMutation(t, st, lockerPID)
	if _, err := tx.ExecContext(ctx,
		`UPDATE devradar_tenant SET status='suspended',updated_at=clock_timestamp() WHERE id=$1`, accountID); err != nil {
		t.Fatalf("suspend locked account: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit suspension: %v", err)
	}
	rec := <-result
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("submit behind suspension = %d, want 500: %s", rec.Code, rec.Body.String())
	}
	select {
	case path := <-blob.putStarted:
		t.Fatalf("inactive account wrote blob %q", path)
	default:
	}
	var rows int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_sbom WHERE tenant_id=$1`, accountID).Scan(&rows); err != nil {
		t.Fatalf("count rejected ingest rows: %v", err)
	}
	if rows != 0 {
		t.Fatalf("rejected inactive ingest left %d SBOM rows", rows)
	}
}

func TestIngestActivationCleanupFailurePreservesPendingRetryRecord(t *testing.T) {
	local := gcs.LocalStore{Dir: t.TempDir()}
	deleteErr := errors.New("blob cleanup unavailable")
	blob := &blockingBlob{
		inner: local, putStarted: make(chan string, 1), releasePut: make(chan struct{}), deleteErr: deleteErr,
	}
	srv, st := serverWithBlob(t, blob)
	accountID, token := seedTenantToken(t, st)
	result := submitSBOMAsync(srv.Handler(), token, submitBody(t))

	objectPath := <-blob.putStarted
	if _, err := st.AdminPrepareAccountDeletion(context.Background(), accountID,
		account.Actor{Kind: account.ActorPlatform}, randomHex(t, 8)); err != nil {
		t.Fatalf("suspend account during Put: %v", err)
	}
	close(blob.releasePut)
	rec := <-result
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("submit with failed compensation = %d, want 500", rec.Code)
	}
	var sbomID, status string
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT id,status FROM devradar_sbom WHERE tenant_id=$1 AND object_path=$2`, accountID, objectPath).
		Scan(&sbomID, &status); err != nil {
		t.Fatalf("read retryable pending record: %v", err)
	}
	if status != "pending" {
		t.Fatalf("cleanup-failed status = %q, want pending", status)
	}
	if _, err := local.Fetch(context.Background(), objectPath); err != nil {
		t.Fatalf("cleanup-failed blob should remain retryable: %v", err)
	}
	if len(blob.deleted) != 1 || blob.deleted[0] != objectPath {
		t.Fatalf("failed cleanup attempts = %q, want exact path %q", blob.deleted, objectPath)
	}
	if _, err := st.DB().ExecContext(context.Background(),
		`UPDATE devradar_sbom SET submitted_at=now()-interval '10 minutes' WHERE id=$1`, sbomID); err != nil {
		t.Fatalf("age retryable pending record: %v", err)
	}
	objects, err := st.AdminPrepareAccountDeletion(context.Background(), accountID,
		account.Actor{Kind: account.ActorPlatform}, randomHex(t, 8))
	if err != nil || len(objects) != 1 || objects[0].SBOMID != sbomID || objects[0].ObjectPath != objectPath {
		t.Fatalf("retryable cleanup batch = %#v, %v", objects, err)
	}
}

func TestIngestActivationAuditFailurePreservesBlobAndPendingRow(t *testing.T) {
	local := gcs.LocalStore{Dir: t.TempDir()}
	releasePut := make(chan struct{})
	close(releasePut)
	blob := &blockingBlob{
		inner: local, putStarted: make(chan string, 1), releasePut: releasePut,
	}
	srv, st := serverWithBlob(t, blob)
	accountID, token := seedTenantToken(t, st)
	constraint := pq.QuoteIdentifier("test_reject_activation_" + randomHex(t, 6))
	if _, err := st.DB().ExecContext(context.Background(), `
		ALTER TABLE devradar_audit_event ADD CONSTRAINT `+constraint+`
		CHECK (account_id <> '`+accountID+`'::uuid OR action <> 'sbom.activate') NOT VALID`); err != nil {
		t.Fatalf("add activation audit failure: %v", err)
	}
	t.Cleanup(func() {
		_, _ = st.DB().ExecContext(context.Background(),
			`ALTER TABLE devradar_audit_event DROP CONSTRAINT IF EXISTS `+constraint)
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/sboms", strings.NewReader(submitBody(t)))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("submit with activation audit failure = %d, want 500: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "failed to activate SBOM") ||
		strings.Contains(rec.Body.String(), "test_reject_activation") {
		t.Fatalf("activation audit failure response was not sanitized: %s", rec.Body.String())
	}
	objectPath := <-blob.putStarted
	var status string
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT status FROM devradar_sbom WHERE tenant_id=$1 AND object_path=$2`, accountID, objectPath).
		Scan(&status); err != nil {
		t.Fatalf("read activation-ambiguous SBOM: %v", err)
	}
	if status != "pending" {
		t.Fatalf("activation-ambiguous SBOM status = %q, want pending", status)
	}
	if _, err := local.Fetch(context.Background(), objectPath); err != nil {
		t.Fatalf("activation-ambiguous blob was removed: %v", err)
	}
	if len(blob.deleted) != 0 {
		t.Fatalf("activation-ambiguous blob deletes = %q, want none", blob.deleted)
	}
}

func submitSBOMAsync(h http.Handler, token, body string) <-chan *httptest.ResponseRecorder {
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/v1/sboms", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		result <- rec
	}()
	return result
}

func waitForBlockedAccountMutation(t *testing.T, st *postgres.Store, lockerPID int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		err := st.DB().QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_stat_activity
				WHERE $1=ANY(pg_blocking_pids(pid))
				  AND query LIKE '%FOR NO KEY UPDATE%'
			)`, lockerPID).Scan(&blocked)
		if err != nil {
			t.Fatalf("observe blocked account mutation: %v", err)
		}
		if blocked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("ingest did not block on the account lifecycle lock")
		case <-ticker.C:
		}
	}
}

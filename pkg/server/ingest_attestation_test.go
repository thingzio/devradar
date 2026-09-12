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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/thingzio/devradar/pkg/attest"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

// submitBodyWithAttestation builds a submit body carrying a base64 attestation.
// The bundle bytes are opaque to the handler (the injected fake verifier does
// not parse them), so any non-empty value exercises the path.
func submitBodyWithAttestation(t *testing.T, attestation string) string {
	t.Helper()
	raw, err := os.ReadFile("../sbom/testdata/redis.syft.cdx.json")
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	body, _ := json.Marshal(map[string]string{
		"sbom":        base64.StdEncoding.EncodeToString(raw),
		"attestation": attestation,
	})
	return string(body)
}

func submitWithVerifier(t *testing.T, v attest.Verifier, body string) (*httptest.ResponseRecorder, *postgres.Store) {
	t.Helper()
	srv, st := serverWithVerifier(t, v)
	_, tok := seedTenantToken(t, st)
	req := httptest.NewRequest(http.MethodPost, "/v1/sboms", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec, st
}

func decodeVerificationStatus(t *testing.T, rec *httptest.ResponseRecorder) (string, string) {
	t.Helper()
	if rec.Code != http.StatusAccepted {
		t.Fatalf("submit = %d, want 202: %s", rec.Code, rec.Body.String())
	}
	var sub struct {
		SBOMID             string `json:"sbom_id"`
		VerificationStatus string `json:"verification_status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sub); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return sub.SBOMID, sub.VerificationStatus
}

// A successful verification flips verification_status to verified, persists
// evidence, and surfaces it on the read API.
func TestIngest_AttestationVerified(t *testing.T) {
	fake := &attest.Fake{Result: &attest.Result{
		Outcome: attest.ResultVerified, Mode: attest.ModeKeyless, Binding: attest.BindingSBOMBytes,
		CertIdentity: "https://github.com/acme/ci", OIDCIssuer: "https://token.actions.githubusercontent.com",
		VerifierVersion: "sigstore-go/test", PolicyVersion: "p1", Envelope: []byte(`{}`),
	}}
	srv, st := serverWithVerifier(t, fake)
	_, tok := seedTenantToken(t, st)
	body := submitBodyWithAttestation(t, base64.StdEncoding.EncodeToString([]byte("bundle")))

	req := httptest.NewRequest(http.MethodPost, "/v1/sboms", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	sbomID, status := decodeVerificationStatus(t, rec)
	if status != attest.ResultVerified {
		t.Fatalf("verification_status = %q, want verified", status)
	}
	if fake.Calls != 1 {
		t.Fatalf("verifier called %d times, want 1", fake.Calls)
	}

	// Evidence persisted.
	got, err := st.GetAttestation(t.Context(), tenantOf(t, st, sbomID), sbomID)
	if err != nil {
		t.Fatalf("evidence not persisted: %v", err)
	}
	if got.Result != attest.ResultVerified || got.CertIdentity != "https://github.com/acme/ci" {
		t.Fatalf("persisted evidence mismatch: %+v", got)
	}

	// Read API surfaces verification_status + evidence.
	getReq := httptest.NewRequest(http.MethodGet, "/v1/sboms/"+sbomID, nil)
	getReq.Header.Set("Authorization", "Bearer "+tok)
	getRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET sbom = %d, want 200: %s", getRec.Code, getRec.Body.String())
	}
	var detail struct {
		VerificationStatus string `json:"verification_status"`
		Attestation        *struct {
			Result       string `json:"result"`
			CertIdentity string `json:"cert_identity"`
		} `json:"attestation"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode sbom detail: %v", err)
	}
	if detail.VerificationStatus != attest.ResultVerified || detail.Attestation == nil ||
		detail.Attestation.CertIdentity != "https://github.com/acme/ci" {
		t.Fatalf("read API evidence mismatch: %+v", detail)
	}
}

// A verifier that returns a failed Result records evidence, sets status=failed,
// and still returns 202 (never blocks ingest).
func TestIngest_AttestationFailedDoesNotBlock(t *testing.T) {
	fake := &attest.Fake{Result: &attest.Result{
		Outcome: attest.ResultFailed, Mode: attest.ModeKeyless, Binding: attest.BindingImageDigest,
		VerifierVersion: "sigstore-go/test", PolicyVersion: "p1",
		FailureReason: "identity not in allow-list", Envelope: []byte(`{}`),
	}}
	rec, _ := submitWithVerifier(t, fake, submitBodyWithAttestation(t, base64.StdEncoding.EncodeToString([]byte("bundle"))))
	_, status := decodeVerificationStatus(t, rec)
	if status != attest.ResultFailed {
		t.Fatalf("verification_status = %q, want failed", status)
	}
}

// A verifier error (could-not-verify) must not fail ingest: 202 with status
// unchanged from the recorded failure path.
func TestIngest_AttestationVerifierErrorDoesNotBlock(t *testing.T) {
	fake := &attest.Fake{Err: errString("verifier exploded")}
	rec, _ := submitWithVerifier(t, fake, submitBodyWithAttestation(t, base64.StdEncoding.EncodeToString([]byte("bundle"))))
	// The handler records a failed result on verifier error; ingest still 202s.
	if rec.Code != http.StatusAccepted {
		t.Fatalf("submit = %d, want 202 despite verifier error: %s", rec.Code, rec.Body.String())
	}
}

// No attestation supplied → status stays unverified even with a verifier present.
func TestIngest_NoAttestationStaysUnverified(t *testing.T) {
	fake := &attest.Fake{Result: &attest.Result{Outcome: attest.ResultVerified}}
	rec, _ := submitWithVerifier(t, fake, submitBody(t))
	_, status := decodeVerificationStatus(t, rec)
	if status != attest.StatusUnverified {
		t.Fatalf("verification_status = %q, want unverified", status)
	}
	if fake.Calls != 0 {
		t.Fatalf("verifier should not be called without an attestation, got %d calls", fake.Calls)
	}
}

// A nil verifier (feature not configured) ignores a supplied attestation.
func TestIngest_NilVerifierIgnoresAttestation(t *testing.T) {
	rec, _ := submitWithVerifier(t, nil, submitBodyWithAttestation(t, base64.StdEncoding.EncodeToString([]byte("bundle"))))
	_, status := decodeVerificationStatus(t, rec)
	if status != attest.StatusUnverified {
		t.Fatalf("verification_status = %q, want unverified with nil verifier", status)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// tenantOf resolves the tenant id owning an SBOM (test helper for evidence reads).
func tenantOf(t *testing.T, st *postgres.Store, sbomID string) string {
	t.Helper()
	var tenantID string
	if err := st.DB().QueryRowContext(t.Context(),
		`SELECT tenant_id FROM devradar_sbom WHERE id=$1`, sbomID).Scan(&tenantID); err != nil {
		t.Fatalf("resolve tenant: %v", err)
	}
	return tenantID
}

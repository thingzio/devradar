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
	"testing"

	"github.com/thingzio/devradar/pkg/attest"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

func verifiedResult(digest string) *attest.Result {
	return &attest.Result{
		Outcome:            attest.ResultVerified,
		Mode:               attest.ModeKeyless,
		Binding:            attest.BindingSBOMBytes,
		SubjectDigest:      digest,
		PredicateType:      "https://cyclonedx.org/bom",
		CertIdentity:       "https://github.com/acme/ci/.github/workflows/release.yml@refs/heads/main",
		OIDCIssuer:         "https://token.actions.githubusercontent.com",
		TransparencyLogRef: "rekor-index-12345",
		VerifierVersion:    "sigstore-go/test",
		PolicyVersion:      "policy-abc",
		Envelope:           []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle+json"}`),
	}
}

func sbomVerificationStatus(t *testing.T, st *postgres.Store, sbomID string) string {
	t.Helper()
	var status string
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT verification_status FROM devradar_sbom WHERE id=$1`, sbomID).Scan(&status); err != nil {
		t.Fatalf("read verification_status: %v", err)
	}
	return status
}

func TestSaveAttestation_VerifiedTransitionAndRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, sb := seedTenantAndSBOM(t, st)

	if got := sbomVerificationStatus(t, st, sb.ID); got != attest.StatusUnverified {
		t.Fatalf("initial verification_status = %q, want unverified", got)
	}

	res := verifiedResult(sb.Digest)
	if err := st.SaveAttestation(ctx, tenantID, sb.ID, res); err != nil {
		t.Fatalf("save attestation: %v", err)
	}

	if got := sbomVerificationStatus(t, st, sb.ID); got != attest.ResultVerified {
		t.Fatalf("verification_status after save = %q, want verified", got)
	}

	got, err := st.GetAttestation(ctx, tenantID, sb.ID)
	if err != nil {
		t.Fatalf("get attestation: %v", err)
	}
	if got.Result != attest.ResultVerified || got.Mode != attest.ModeKeyless ||
		got.Binding != attest.BindingSBOMBytes || got.SubjectDigest != sb.Digest ||
		got.CertIdentity != res.CertIdentity || got.OIDCIssuer != res.OIDCIssuer ||
		got.TransparencyLogRef != res.TransparencyLogRef || got.PredicateType != res.PredicateType {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestSaveAttestation_Idempotent(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, sb := seedTenantAndSBOM(t, st)

	res := verifiedResult(sb.Digest)
	for i := range 3 {
		if err := st.SaveAttestation(ctx, tenantID, sb.ID, res); err != nil {
			t.Fatalf("save attestation #%d: %v", i, err)
		}
	}
	var n int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_sbom_attestation WHERE sbom_id=$1`, sb.ID).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("attestation rows = %d, want exactly 1 (idempotent on natural key)", n)
	}
}

func TestSaveAttestation_FailedRecorded(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, sb := seedTenantAndSBOM(t, st)

	res := &attest.Result{
		Outcome:         attest.ResultFailed,
		Mode:            attest.ModeKey,
		Binding:         attest.BindingImageDigest,
		SubjectDigest:   sb.Digest,
		VerifierVersion: "sigstore-go/test",
		PolicyVersion:   "policy-abc",
		FailureReason:   "certificate identity not in allow-list",
		Envelope:        []byte(`{}`),
	}
	if err := st.SaveAttestation(ctx, tenantID, sb.ID, res); err != nil {
		t.Fatalf("save failed attestation: %v", err)
	}
	if got := sbomVerificationStatus(t, st, sb.ID); got != attest.ResultFailed {
		t.Fatalf("verification_status = %q, want failed", got)
	}
	got, err := st.GetAttestation(ctx, tenantID, sb.ID)
	if err != nil {
		t.Fatalf("get attestation: %v", err)
	}
	if got.Result != attest.ResultFailed || got.FailureReason != res.FailureReason || got.Mode != attest.ModeKey {
		t.Fatalf("failed round-trip mismatch: %+v", got)
	}
}

func TestSaveAttestation_TenantIsolationAndNotFound(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, sb := seedTenantAndSBOM(t, st)
	otherTenant, _ := seedTenantAndSBOM(t, st)

	if _, err := st.GetAttestation(ctx, tenantID, sb.ID); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("expected ErrNotFound before save, got %v", err)
	}
	if err := st.SaveAttestation(ctx, tenantID, sb.ID, verifiedResult(sb.Digest)); err != nil {
		t.Fatalf("save: %v", err)
	}
	// A different tenant must not see it.
	if _, err := st.GetAttestation(ctx, otherTenant, sb.ID); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("cross-tenant read = %v, want ErrNotFound", err)
	}
}

func TestSaveAttestation_CascadesOnSBOMArchiveDelete(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, sb := seedTenantAndSBOM(t, st)

	if err := st.SaveAttestation(ctx, tenantID, sb.ID, verifiedResult(sb.Digest)); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Hard-delete the SBOM row; the evidence row must cascade away.
	if _, err := st.DB().ExecContext(ctx, `DELETE FROM devradar_sbom WHERE id=$1`, sb.ID); err != nil {
		t.Fatalf("delete sbom: %v", err)
	}
	var n int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_sbom_attestation WHERE sbom_id=$1`, sb.ID).Scan(&n); err != nil {
		t.Fatalf("count after cascade: %v", err)
	}
	if n != 0 {
		t.Fatalf("attestation rows after sbom delete = %d, want 0 (ON DELETE CASCADE)", n)
	}
}

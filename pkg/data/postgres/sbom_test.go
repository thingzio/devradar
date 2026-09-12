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

	"github.com/thingzio/devradar/pkg/data/postgres"
)

func TestUpsertSBOMWithLimitRejectsInactiveAndMissingAccounts(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	var accountID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email,status) VALUES ($1,'suspended') RETURNING id`,
		"inactive-"+randID(t)[:8]+"@example.com").Scan(&accountID); err != nil {
		t.Fatalf("seed suspended account: %v", err)
	}
	newSBOM := func(id string) *postgres.SBOM {
		return &postgres.SBOM{
			ID: id + randID(t), TenantID: accountID,
			ImageRef: "registry.test/inactive", Repository: "registry.test/inactive",
			Digest: "sha256:" + randID(t) + randID(t), Format: "cyclonedx",
			ObjectPath: "gs://test/" + accountID + "/" + id, Status: "pending",
		}
	}

	if _, _, _, err := st.UpsertSBOMWithLimit(ctx, newSBOM(randID(t)), 0, 0); !errors.Is(err, postgres.ErrAccountInactive) {
		t.Fatalf("suspended-account upsert error = %v, want ErrAccountInactive", err)
	}
	if _, err := st.DB().ExecContext(ctx, `DELETE FROM devradar_tenant WHERE id=$1`, accountID); err != nil {
		t.Fatalf("delete account: %v", err)
	}
	if _, _, _, err := st.UpsertSBOMWithLimit(ctx, newSBOM(randID(t)), 0, 0); !errors.Is(err, postgres.ErrNotFound) {
		t.Fatalf("missing-account upsert error = %v, want ErrNotFound", err)
	}
}

// TestUpsertSBOMWithLimit_ActiveCap verifies the per-tenant active-SBOM cap:
// distinct digests are admitted up to the cap, a brand-new digest past it is
// rejected with ErrSBOMLimit, and a re-submit of an existing digest is always
// admitted (even at the cap) since it is an update, not growth.
func TestUpsertSBOMWithLimit_ActiveCap(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	var tenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"cap-"+randID(t)[:8]+"@example.com").Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	const cap = 3
	mk := func() *postgres.SBOM {
		return &postgres.SBOM{
			ID:         randID(t) + randID(t),
			TenantID:   tenantID,
			ImageRef:   "registry.test/app",
			Repository: "registry.test/app",
			Digest:     "sha256:" + randID(t) + randID(t),
			Format:     "cyclonedx",
			ObjectPath: "gs://test/" + tenantID + "/" + randID(t),
			Status:     "active",
		}
	}

	// Fill to the cap with distinct digests (repo cap disabled: all one repo).
	var lastDigest, lastFormat string
	for i := range cap {
		sb := mk()
		lastDigest, lastFormat = sb.Digest, sb.Format
		if _, inserted, _, err := st.UpsertSBOMWithLimit(ctx, sb, cap, 0); err != nil || !inserted {
			t.Fatalf("submit %d under cap: inserted=%v err=%v", i, inserted, err)
		}
	}

	// A brand-new digest past the cap is rejected.
	if _, _, _, err := st.UpsertSBOMWithLimit(ctx, mk(), cap, 0); !errors.Is(err, postgres.ErrSBOMLimit) {
		t.Fatalf("over-cap submit: err = %v, want ErrSBOMLimit", err)
	}

	// A re-submit of an EXISTING digest is still admitted at the cap (update, not
	// growth) — resolves to the existing row (inserted=false), no error.
	resub := mk()
	resub.Digest, resub.Format = lastDigest, lastFormat
	if _, inserted, _, err := st.UpsertSBOMWithLimit(ctx, resub, cap, 0); err != nil || inserted {
		t.Fatalf("re-submit at cap: inserted=%v err=%v, want inserted=false nil", inserted, err)
	}

	// A cap of 0 disables enforcement.
	if _, inserted, _, err := st.UpsertSBOMWithLimit(ctx, mk(), 0, 0); err != nil || !inserted {
		t.Fatalf("cap disabled: inserted=%v err=%v", inserted, err)
	}
}

// TestUpsertSBOMWithLimit_RepoCap verifies the per-tenant repository cap:
// distinct repositories are admitted up to maxRepos, a brand-new repository past
// it returns ErrImageLimit, but a NEW digest under an already-tracked repository
// is always admitted (not new-repo growth).
func TestUpsertSBOMWithLimit_RepoCap(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	var tenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"repocap-"+randID(t)[:8]+"@example.com").Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	const maxRepos = 2
	mk := func(repo string) *postgres.SBOM {
		return &postgres.SBOM{
			ID: randID(t) + randID(t), TenantID: tenantID,
			ImageRef: repo, Repository: repo,
			Digest: "sha256:" + randID(t) + randID(t), Format: "cyclonedx",
			ObjectPath: "gs://test/" + tenantID + "/" + randID(t), Status: "active",
		}
	}

	for i, repo := range []string{"registry.test/a", "registry.test/b"} {
		if _, inserted, _, err := st.UpsertSBOMWithLimit(ctx, mk(repo), 0, maxRepos); err != nil || !inserted {
			t.Fatalf("repo %d under cap: inserted=%v err=%v", i, inserted, err)
		}
	}

	// A brand-new repository past the cap is rejected.
	if _, _, _, err := st.UpsertSBOMWithLimit(ctx, mk("registry.test/c"), 0, maxRepos); !errors.Is(err, postgres.ErrImageLimit) {
		t.Fatalf("over-cap new repo: err = %v, want ErrImageLimit", err)
	}

	// A NEW digest under an ALREADY-TRACKED repository is admitted even at the cap.
	if _, inserted, _, err := st.UpsertSBOMWithLimit(ctx, mk("registry.test/a"), 0, maxRepos); err != nil || !inserted {
		t.Fatalf("new digest under tracked repo at cap: inserted=%v err=%v", inserted, err)
	}
}

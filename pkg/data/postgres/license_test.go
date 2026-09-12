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
	"testing"

	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

func TestUpsertSBOMPackages_Idempotent(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, sb := seedTenantAndSBOM(t, st)

	pkgs := []data.PackageLicense{
		{Package: "apt", Version: "3.0.3", PURL: "pkg:deb/debian/apt@3.0.3", Licenses: []string{"GPL-2.0-only", "MIT"}},
		{Package: "openssl", Version: "3.0", Licenses: []string{"Apache-2.0"}},
		{Package: "mystery", Version: "1.0"}, // no license → unknown
	}
	if err := st.UpsertSBOMPackages(ctx, sb.ID, pkgs); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	// Re-run must be a no-op (frozen inventory) — no error, no duplication.
	if err := st.UpsertSBOMPackages(ctx, sb.ID, pkgs); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	rows, err := st.ListSBOMPackages(ctx, tenantID, sb.ID, data.LicensePolicy{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d packages, want 3 (idempotent)", len(rows))
	}
}

func TestListSBOMPackages_ClassifiesAndEvaluates(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, sb := seedTenantAndSBOM(t, st)

	pkgs := []data.PackageLicense{
		{Package: "apt", Version: "3.0.3", Licenses: []string{"GPL-2.0-only", "MIT"}},
		{Package: "openssl", Version: "3.0", Licenses: []string{"Apache-2.0"}},
	}
	if err := st.UpsertSBOMPackages(ctx, sb.ID, pkgs); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	policy := data.LicensePolicy{DeniedCategories: []data.LicenseCategory{data.CategoryStrongCopyleft}}
	rows, err := st.ListSBOMPackages(ctx, tenantID, sb.ID, policy)
	if err != nil {
		t.Fatalf("list: %v", err)
	}

	byName := map[string]postgres.PackageLicenseRow{}
	for _, r := range rows {
		byName[r.Package] = r
	}
	// apt carries GPL-2.0 AND MIT (separate entries = conjunction) → violates.
	if !byName["apt"].Violation {
		t.Errorf("apt should violate strong-copyleft policy: %+v", byName["apt"])
	}
	if byName["apt"].Category != string(data.CategoryStrongCopyleft) {
		t.Errorf("apt worst category = %q, want strong-copyleft", byName["apt"].Category)
	}
	// openssl (Apache-2.0) is permissive → compliant.
	if byName["openssl"].Violation {
		t.Errorf("openssl should be compliant: %+v", byName["openssl"])
	}
	// Violations sort first.
	if rows[0].Package != "apt" {
		t.Errorf("violations should sort first, got %q", rows[0].Package)
	}
}

func TestFleetLicenseStats(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, sb := seedTenantAndSBOM(t, st)

	pkgs := []data.PackageLicense{
		{Package: "a", Version: "1", Licenses: []string{"MIT"}},
		{Package: "b", Version: "1", Licenses: []string{"GPL-3.0"}},
		{Package: "c", Version: "1", Licenses: []string{"Apache-2.0"}},
		{Package: "d", Version: "1"}, // unlicensed
	}
	if err := st.UpsertSBOMPackages(ctx, sb.ID, pkgs); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	policy := data.LicensePolicy{DeniedCategories: []data.LicenseCategory{data.CategoryStrongCopyleft}}
	fs, err := st.FleetLicenseStats(ctx, tenantID, policy)
	if err != nil {
		t.Fatalf("fleet stats: %v", err)
	}
	if fs.Packages != 4 {
		t.Errorf("packages = %d, want 4", fs.Packages)
	}
	if fs.Unlicensed != 1 {
		t.Errorf("unlicensed = %d, want 1", fs.Unlicensed)
	}
	if fs.Violations != 1 { // only GPL-3.0
		t.Errorf("violations = %d, want 1", fs.Violations)
	}
	if len(fs.Categories) == 0 {
		t.Error("expected non-empty category distribution")
	}
}

func TestLicensePolicyRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantID, _ := seedTenantAndSBOM(t, st)

	// Default is empty.
	p, err := st.GetLicensePolicy(ctx, tenantID)
	if err != nil {
		t.Fatalf("get default policy: %v", err)
	}
	if !p.IsEmpty() {
		t.Errorf("default policy should be empty, got %+v", p)
	}

	want := data.LicensePolicy{
		DeniedCategories: []data.LicenseCategory{data.CategoryStrongCopyleft, data.CategoryProprietary},
		AllowExceptions:  []string{"GPL-2.0"},
		DenyExceptions:   []string{"MIT"},
	}
	if err := st.SetLicensePolicy(ctx, tenantID, want); err != nil {
		t.Fatalf("set policy: %v", err)
	}
	got, err := st.GetLicensePolicy(ctx, tenantID)
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if len(got.DeniedCategories) != 2 || len(got.AllowExceptions) != 1 || len(got.DenyExceptions) != 1 {
		t.Errorf("round-trip mismatch: %+v", got)
	}

	// Update replaces (not appends).
	if err := st.SetLicensePolicy(ctx, tenantID, data.LicensePolicy{
		DeniedCategories: []data.LicenseCategory{data.CategoryUnknown},
	}); err != nil {
		t.Fatalf("update policy: %v", err)
	}
	got, _ = st.GetLicensePolicy(ctx, tenantID)
	if len(got.DeniedCategories) != 1 || got.DeniedCategories[0] != data.CategoryUnknown {
		t.Errorf("update should replace, got %+v", got.DeniedCategories)
	}
}

func TestListSBOMPackages_CrossTenantIsolation(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	tenantA, sbA := seedTenantAndSBOM(t, st)
	tenantB, _ := seedTenantAndSBOM(t, st)

	if err := st.UpsertSBOMPackages(ctx, sbA.ID, []data.PackageLicense{
		{Package: "secret", Version: "1", Licenses: []string{"MIT"}},
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Tenant B must not see tenant A's SBOM packages (ownership check → ErrNotFound).
	if _, err := st.ListSBOMPackages(ctx, tenantB, sbA.ID, data.LicensePolicy{}); err == nil {
		t.Error("tenant B should not read tenant A's packages")
	}
	// Tenant B's fleet stats must be empty.
	fs, err := st.FleetLicenseStats(ctx, tenantB, data.LicensePolicy{})
	if err != nil {
		t.Fatalf("fleet stats B: %v", err)
	}
	if fs.Packages != 0 {
		t.Errorf("tenant B fleet should be empty, got %d packages", fs.Packages)
	}
	_ = tenantA
}

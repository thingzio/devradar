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

// TestScanFailureClassification verifies the zero-findings tripwire is counted
// and surfaced as a warning, while a genuine stage failure counts as an error —
// the read-time split that keeps the dashboard's red failure count honest.
func TestScanFailureClassification(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	db := st.DB()

	// Isolate: only assert on rows this test creates.
	if _, err := db.ExecContext(ctx, `DELETE FROM devradar_scan_failure`); err != nil {
		t.Fatalf("clean failures: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM devradar_scan_failure`) })

	// One real failure + two zero-findings warnings.
	st.RecordScanFailure(ctx, "sbom-a", "trivy", "scan", errors.New("boom"))
	st.RecordScanFailure(ctx, "sbom-b", "trivy", postgres.WarningStage, errors.New("0 findings on sbom with 663 packages"))
	st.RecordScanFailure(ctx, "sbom-c", "trivy", postgres.WarningStage, errors.New("0 findings on sbom with 703 packages"))

	pc, err := st.AdminPlatformCounts(ctx)
	if err != nil {
		t.Fatalf("platform counts: %v", err)
	}
	if pc.Failures24h != 1 {
		t.Errorf("Failures24h = %d, want 1 (real errors only)", pc.Failures24h)
	}
	if pc.Warnings24h != 2 {
		t.Errorf("Warnings24h = %d, want 2 (zero-findings)", pc.Warnings24h)
	}

	rows, err := st.AdminRecentFailures(ctx, "", 50)
	if err != nil {
		t.Fatalf("recent failures: %v", err)
	}
	var errs, warns int
	for _, r := range rows {
		if r.IsWarning() {
			warns++
		} else {
			errs++
		}
	}
	if errs != 1 || warns != 2 {
		t.Errorf("row split = %d errors / %d warnings, want 1 / 2", errs, warns)
	}
}

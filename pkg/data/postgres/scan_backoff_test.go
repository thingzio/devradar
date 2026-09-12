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
)

// TestScannerBackoff verifies the per-(SBOM, scanner) backoff lifecycle: a fresh
// pair is due, a recorded failure pushes next_attempt into the future (not due),
// enough failures quarantine it, and a clear (success) makes it due again.
func TestScannerBackoff(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	_, sb := seedTenantAndSBOM(t, st)
	const scanner = "grype"

	// Fresh pair (no row) → due.
	if due, err := st.ScannerAttemptDue(ctx, sb.ID, scanner); err != nil || !due {
		t.Fatalf("fresh pair: due=%v err=%v, want due", due, err)
	}

	// One failure → backing off (next_attempt in the future) → not due.
	if err := st.RecordScannerAttemptFailure(ctx, sb.ID, scanner, "scan: boom"); err != nil {
		t.Fatalf("record failure: %v", err)
	}
	if due, err := st.ScannerAttemptDue(ctx, sb.ID, scanner); err != nil || due {
		t.Fatalf("after 1 failure: due=%v err=%v, want NOT due", due, err)
	}

	// Success clears the state → due again immediately.
	if err := st.ClearScannerAttempt(ctx, sb.ID, scanner); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if due, err := st.ScannerAttemptDue(ctx, sb.ID, scanner); err != nil || !due {
		t.Fatalf("after clear: due=%v err=%v, want due", due, err)
	}

	// Drive it to quarantine: repeated failures. Once quarantined, it stays NOT
	// due regardless of time.
	for range 8 {
		if err := st.RecordScannerAttemptFailure(ctx, sb.ID, scanner, "scan: boom"); err != nil {
			t.Fatalf("record failure: %v", err)
		}
	}
	var quarantined bool
	if err := st.DB().QueryRowContext(ctx,
		`SELECT quarantined FROM devradar_scan_attempt WHERE sbom_id=$1 AND scanner=$2`,
		sb.ID, scanner).Scan(&quarantined); err != nil {
		t.Fatalf("read quarantine: %v", err)
	}
	if !quarantined {
		t.Error("pair should be quarantined after repeated failures")
	}
	if due, _ := st.ScannerAttemptDue(ctx, sb.ID, scanner); due {
		t.Error("quarantined pair must not be due")
	}

	// A clear resets even a quarantined pair (operator-triggered recovery path).
	if err := st.ClearScannerAttempt(ctx, sb.ID, scanner); err != nil {
		t.Fatalf("clear quarantined: %v", err)
	}
	if due, _ := st.ScannerAttemptDue(ctx, sb.ID, scanner); !due {
		t.Error("pair should be due after clearing quarantine")
	}
}

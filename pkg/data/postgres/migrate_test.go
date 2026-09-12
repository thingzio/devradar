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
	"fmt"
	"testing"
	"time"
)

// TestEnsureEventPartitions_CreatesAheadAndIdempotent verifies the rolling
// partition maintenance: the current month + 3 ahead exist as real partitions
// of devradar_finding_event, and re-running is a no-op (safe on every boot).
func TestEnsureEventPartitions_CreatesAheadAndIdempotent(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	// Use a fixed far-future base so the partitions we assert on don't collide
	// with the ones New() already created for the real current month.
	base := time.Date(2031, time.March, 15, 0, 0, 0, 0, time.UTC)
	if err := st.EnsureEventPartitions(ctx, base); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	// Idempotent: a second call must not error.
	if err := st.EnsureEventPartitions(ctx, base); err != nil {
		t.Fatalf("ensure (2nd): %v", err)
	}

	// current month + 3 ahead = Mar..Jun 2031.
	for _, m := range []time.Month{time.March, time.April, time.May, time.June} {
		name := fmt.Sprintf("devradar_finding_event_2031_%02d", int(m))
		var exists bool
		if err := st.DB().QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM pg_class WHERE relname = $1 AND relkind = 'r')`,
			name).Scan(&exists); err != nil {
			t.Fatalf("check %s: %v", name, err)
		}
		if !exists {
			t.Errorf("partition %s should exist", name)
		}
	}

	// A far-future month NOT covered should not exist (proves the window is bounded).
	var extra bool
	_ = st.DB().QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM pg_class WHERE relname = 'devradar_finding_event_2031_08')`).Scan(&extra)
	if extra {
		t.Error("2031_08 should not have been created (beyond the ahead window)")
	}
}

// TestMigrate_Idempotent verifies re-running Migrate applies nothing new and
// leaves exactly one recorded version per migration file. With migration+record
// now atomic, a re-run is a clean no-op — no duplicate version rows, no
// re-applied DDL.
func TestMigrate_Idempotent(t *testing.T) {
	st := testStore(t) // New() already ran Migrate once on connect
	ctx := context.Background()

	rowsBefore := func() int {
		var n int
		if err := st.DB().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM devradar_schema_version`).Scan(&n); err != nil {
			t.Fatalf("count versions: %v", err)
		}
		return n
	}
	before := rowsBefore()

	// Re-run: must be a no-op (every version already recorded).
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("re-run migrate: %v", err)
	}
	after := rowsBefore()
	if after != before {
		t.Errorf("schema_version rows changed on re-run: before=%d after=%d", before, after)
	}

	// No duplicate versions (the atomic apply+record guarantees one row each).
	var dupes int
	if err := st.DB().QueryRowContext(ctx, `
		SELECT COUNT(*) FROM (
			SELECT version FROM devradar_schema_version GROUP BY version HAVING COUNT(*) > 1
		) d`).Scan(&dupes); err != nil {
		t.Fatalf("check dupes: %v", err)
	}
	if dupes != 0 {
		t.Errorf("found %d duplicated migration versions", dupes)
	}
}

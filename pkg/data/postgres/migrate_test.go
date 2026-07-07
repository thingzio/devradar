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

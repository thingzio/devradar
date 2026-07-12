package postgres_test

import (
	"context"
	"testing"
)

// TestSnapshotPlatformStats_UpsertAndDeltas verifies a snapshot is recorded
// idempotently within a day and that PlatformDeltas subtracts the newest
// on-or-before-horizon snapshot from the current one. It starts from a clean
// devradar_platform_stats table (shared test DB) and cleans up after itself.
func TestSnapshotPlatformStats_UpsertAndDeltas(t *testing.T) {
	// SnapshotPlatformStats and the delta assertions read GLOBAL cross-tenant
	// state (devradar_platform_stats row counts, the tenant count). A private
	// schema keeps concurrent package tests on the shared DB from drifting those
	// counts under `go test -race ./...`.
	st := isolatedAdminProductHealthStore(t)
	ctx := context.Background()
	db := st.DB()

	if _, err := db.ExecContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ('snap-'||gen_random_uuid()||'@example.com')`); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	snap, err := st.SnapshotPlatformStats(ctx)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap.Tenants < 1 {
		t.Fatalf("snapshot tenants = %d, want >= 1", snap.Tenants)
	}

	// Idempotent within the day: a second snapshot UPSERTs the same row.
	if _, err := st.SnapshotPlatformStats(ctx); err != nil {
		t.Fatalf("second snapshot: %v", err)
	}
	var rows int
	if err := db.QueryRowContext(ctx,
		`SELECT count(*) FROM devradar_platform_stats`).Scan(&rows); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rows != 1 {
		t.Errorf("snapshot rows = %d, want exactly 1 (UPSERT within a day)", rows)
	}

	// Only today's snapshot exists → every horizon lacks a baseline (Has=false).
	deltas, err := st.PlatformDeltas(ctx, []int{1, 7, 30})
	if err != nil {
		t.Fatalf("deltas: %v", err)
	}
	for _, h := range []int{1, 7, 30} {
		if deltas[h]["tenants"].Has {
			t.Errorf("horizon %d: Has=true, want false with no baseline snapshot", h)
		}
	}

	// Backdate a baseline 7 days ago with 0 tenants; the week delta then reflects
	// current tenants - 0 = current.
	if _, err := db.ExecContext(ctx, `
		INSERT INTO devradar_platform_stats (snapshot_date, tenants)
		VALUES ((now() AT TIME ZONE 'UTC')::date - interval '7 days', 0)`); err != nil {
		t.Fatalf("backdate baseline: %v", err)
	}
	deltas, err = st.PlatformDeltas(ctx, []int{7})
	if err != nil {
		t.Fatalf("deltas after baseline: %v", err)
	}
	cell := deltas[7]["tenants"]
	if !cell.Has {
		t.Fatal("horizon 7: Has=false, want true after backdating a baseline")
	}
	if cell.Delta != snap.Tenants {
		t.Errorf("horizon 7 tenants delta = %d, want %d (current - 0)", cell.Delta, snap.Tenants)
	}
}

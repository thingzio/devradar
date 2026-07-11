package postgres

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed sql/migrations/*.sql
var migrationsFS embed.FS

// migrateLockKey is the Postgres advisory-lock key held for the duration of all
// schema applies. Concurrent boot from scale-to-zero can land two replicas in
// Migrate at the same instant; the lock serializes them. The value is the ASCII
// bytes of "devradar" (8 bytes → int64), distinct from the sibling services'
// keys ("devtrace", "devpulse") so nothing collides in the shared instance.
const migrateLockKey int64 = 0x6465767261646172 // "devradar"

// schemaVersionTable tracks applied migration versions.
const schemaVersionTable = "devradar_schema_version"

// Migrate applies any not-yet-applied migrations in filename order. Migrations
// are NNN_name.sql; the numeric prefix is the version. All applies run on a
// single pinned connection under the advisory lock (Postgres advisory locks are
// session-scoped, so lock + apply + unlock must share one connection).
func (s *Store) Migrate(ctx context.Context) error {
	entries, err := migrationsFS.ReadDir("sql/migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration conn: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", migrateLockKey); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", migrateLockKey); err != nil {
			slog.Warn("release migration lock", "error", err)
		}
	}()

	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		version, err := strconv.Atoi(strings.Split(name, "_")[0])
		if err != nil {
			return fmt.Errorf("parse migration version %q: %w", name, err)
		}

		applied, err := migrationApplied(ctx, conn, version)
		if err != nil {
			return fmt.Errorf("check migration %d: %w", version, err)
		}
		if applied {
			continue
		}

		data, err := migrationsFS.ReadFile("sql/migrations/" + name)
		if err != nil {
			return fmt.Errorf("read migration %q: %w", name, err)
		}

		slog.Info("applying migration", "version", version, "file", name)
		// Apply the migration and record its version in ONE transaction on the
		// advisory-locked connection. Postgres DDL is transactional, so a crash
		// between the two statements can no longer leave a migration applied but
		// unrecorded (which would re-run it next boot and make idempotency an
		// undocumented permanent requirement). Either both land or neither does.
		if err := applyOne(ctx, conn, name, version, string(data)); err != nil {
			return err
		}
	}
	return nil
}

// applyOne runs one migration's SQL and records its version atomically, in a
// single transaction on the given (advisory-locked) connection.
func applyOne(ctx context.Context, conn *sql.Conn, name string, version int, ddl string) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration %q: %w", name, err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit

	if _, err := tx.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("apply migration %q: %w", name, err)
	}
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO "+schemaVersionTable+" (version) VALUES ($1) ON CONFLICT DO NOTHING", version); err != nil {
		return fmt.Errorf("record migration %d: %w", version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %q: %w", name, err)
	}
	return nil
}

// partitionMonthsAhead is how many future monthly partitions of
// devradar_finding_event to pre-create. The daily scan job runs Migrate (and
// thus this) at least monthly, and this keeps partitions well ahead of now(),
// so events never fall into the catch-all DEFAULT partition — which, once it
// holds rows, would block creating that month's real partition.
const partitionMonthsAhead = 3

// EnsureEventPartitions idempotently creates monthly partitions of
// devradar_finding_event for the current month through partitionMonthsAhead
// months out. Safe to run on every boot (CREATE TABLE IF NOT EXISTS). base is
// normally time.Now().UTC(); it is a parameter so the logic is unit-testable.
func (s *Store) EnsureEventPartitions(ctx context.Context, base time.Time) error {
	base = base.UTC()
	for i := 0; i <= partitionMonthsAhead; i++ {
		start := time.Date(base.Year(), base.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, i, 0)
		end := start.AddDate(0, 1, 0)
		name := fmt.Sprintf("devradar_finding_event_%04d_%02d", start.Year(), int(start.Month()))
		// Identifiers/dates are code-derived (not user input); values are formatted
		// as literals because PARTITION bounds cannot be parameterized.
		stmt := fmt.Sprintf(
			`CREATE TABLE IF NOT EXISTS %s PARTITION OF devradar_finding_event FOR VALUES FROM ('%s') TO ('%s')`,
			name, start.Format("2006-01-02"), end.Format("2006-01-02"))
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("ensure partition %s: %w", name, err)
		}
	}
	return nil
}

func migrationApplied(ctx context.Context, conn *sql.Conn, version int) (bool, error) {
	var exists bool
	if err := conn.QueryRowContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = $1)",
		schemaVersionTable).Scan(&exists); err != nil {
		return false, fmt.Errorf("check schema table: %w", err)
	}
	if !exists {
		return false, nil
	}
	var count int
	if err := conn.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM "+schemaVersionTable+" WHERE version = $1", version).Scan(&count); err != nil {
		return false, fmt.Errorf("check migration version: %w", err)
	}
	return count > 0, nil
}

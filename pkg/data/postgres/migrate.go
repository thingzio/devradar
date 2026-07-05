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
	defer conn.Close()

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
		if _, err := conn.ExecContext(ctx, string(data)); err != nil {
			return fmt.Errorf("apply migration %q: %w", name, err)
		}
		if _, err := conn.ExecContext(ctx,
			"INSERT INTO "+schemaVersionTable+" (version) VALUES ($1) ON CONFLICT DO NOTHING", version); err != nil {
			return fmt.Errorf("record migration %d: %w", version, err)
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

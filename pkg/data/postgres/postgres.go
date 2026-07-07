// Package postgres is DevRadar's data store over the shared Thingz Postgres
// instance. It uses database/sql with the lib/pq driver (matching DevPulse and
// DevTrace — not pgx), and every object it creates is prefixed devradar_ so it
// cannot collide with the sibling services in the shared `thingz` database.
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/thingzio/devradar/pkg/config"
)

// Store wraps the connection pool. Tenant isolation is enforced in the query
// layer (WHERE tenant_id = $1), not via RLS — see the design docs for why.
type Store struct {
	db *sql.DB
}

// PoolConfig tunes the connection pool. AppName is stamped as the Postgres
// application_name so connections are attributable in the shared instance.
type PoolConfig struct {
	AppName         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

// DefaultPoolConfig is sized for the ingest/serve service.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		AppName:         "devradar-serve",
		MaxOpenConns:    config.GetEnvAsInt("DB_MAX_OPEN_CONNS", 10),
		MaxIdleConns:    config.GetEnvAsInt("DB_MAX_IDLE_CONNS", 5),
		ConnMaxLifetime: 30 * time.Minute,
		ConnMaxIdleTime: 5 * time.Minute,
	}
}

// ScanPoolConfig is sized for the daily scan job — a single serial worker, so a
// small pool suffices.
func ScanPoolConfig() PoolConfig {
	cfg := DefaultPoolConfig()
	cfg.AppName = "devradar-scan"
	cfg.MaxOpenConns = config.GetEnvAsInt("DB_MAX_OPEN_CONNS", 4)
	cfg.MaxIdleConns = config.GetEnvAsInt("DB_MAX_IDLE_CONNS", 2)
	return cfg
}

// applyAppName appends application_name to a DSN if not already present,
// handling both URI and keyword DSN forms.
func applyAppName(dsn, appName string) string {
	if appName == "" || strings.Contains(dsn, "application_name") {
		return dsn
	}
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		if strings.Contains(dsn, "?") {
			return dsn + "&application_name=" + appName
		}
		return dsn + "?application_name=" + appName
	}
	return dsn + " application_name=" + appName
}

// New opens the pool, verifies connectivity, and runs migrations.
func New(ctx context.Context, dsn string, cfg PoolConfig) (*Store, error) {
	db, err := sql.Open("postgres", applyAppName(dsn, cfg.AppName))
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}

	s := &Store{db: db}
	if err := s.Migrate(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	// Keep the append-only event log's monthly partitions ahead of now() so rows
	// never fall into the DEFAULT partition. Idempotent; runs every boot.
	if err := s.EnsureEventPartitions(ctx, time.Now()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ensure event partitions: %w", err)
	}
	return s, nil
}

// NewFromEnv builds a Store from DATABASE_URL with the default pool config.
func NewFromEnv(ctx context.Context) (*Store, error) {
	return New(ctx, config.DatabaseURL(), DefaultPoolConfig())
}

// DB exposes the underlying pool for callers that run their own queries.
func (s *Store) DB() *sql.DB { return s.db }

// Close closes the pool.
func (s *Store) Close() error { return s.db.Close() }

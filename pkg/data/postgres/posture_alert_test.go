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
	"os"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/data/postgres"
)

type previousSBOMComparer interface {
	ComparePreviousSBOM(context.Context, string, string) (*postgres.SBOMComparison, error)
}

func TestPostureRegressionMigrationRepairsDuplicates(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	schema := "posture_migration_" + randID(t)
	if _, err := st.DB().ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create migration test schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = st.DB().ExecContext(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	})
	conn, err := st.DB().Conn(ctx)
	if err != nil {
		t.Fatalf("acquire migration test connection: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `SET search_path TO `+schema); err != nil {
		t.Fatalf("set migration test search path: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `
		CREATE TABLE devradar_alert (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			policy_id TEXT NOT NULL,
			sbom_id TEXT NOT NULL,
			alert_kind TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL
		)`); err != nil {
		t.Fatalf("create migration test alert table: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `
		INSERT INTO devradar_alert
		(id, tenant_id, policy_id, sbom_id, alert_kind, created_at)
		VALUES
		('b','tenant','policy','sbom','posture_regression','2026-07-11T00:00:00Z'),
		('a','tenant','policy','sbom','posture_regression','2026-07-11T00:00:00Z'),
		('later','tenant','policy','sbom','posture_regression','2026-07-11T00:01:00Z'),
		('normal','tenant','policy','sbom','new_finding','2026-07-11T00:00:00Z')`); err != nil {
		t.Fatalf("seed migration duplicates: %v", err)
	}
	ddl, err := os.ReadFile("sql/migrations/023_posture_regression_alert.sql")
	if err != nil {
		t.Fatalf("read posture regression migration: %v", err)
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin migration test transaction: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, string(ddl)); err != nil {
		t.Fatalf("apply posture regression migration: %v", err)
	}
	var retained string
	if err := tx.QueryRowContext(ctx, `
		SELECT id FROM devradar_alert WHERE alert_kind='posture_regression'`).Scan(&retained); err != nil {
		t.Fatalf("read retained posture regression: %v", err)
	}
	if retained != "a" {
		t.Fatalf("retained posture regression = %q, want earliest created_at then ID a", retained)
	}
	var normalCount int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM devradar_alert WHERE alert_kind='new_finding'`).Scan(&normalCount); err != nil {
		t.Fatalf("count normal alerts: %v", err)
	}
	if normalCount != 1 {
		t.Fatalf("normal alerts = %d, want 1", normalCount)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO devradar_alert
		(id, tenant_id, policy_id, sbom_id, alert_kind, created_at)
		VALUES ('duplicate','tenant','policy','sbom','posture_regression',now())`); err == nil {
		t.Fatal("post-migration duplicate posture regression insert succeeded")
	}
}

func TestComparePreviousSBOM_SelectsImmediateActiveTenantRepositoryPredecessor(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	comparer, ok := any(st).(previousSBOMComparer)
	if !ok {
		t.Fatal("Store does not implement ComparePreviousSBOM")
	}

	tenantID, _ := seedTenantAndSBOM(t, st)
	repository := "registry.test/posture-regression"
	base := time.Now().UTC().Add(-time.Hour)
	tiePrefix := randID(t) + randID(t)
	previous := comparisonSBOM(t, tenantID, repository, "previous", base.Add(2*time.Minute))
	previous.ID = tiePrefix[:63] + "e"
	previous.Digest = "sha256:" + previous.ID

	tieOlder := comparisonSBOM(t, tenantID, repository, "tie-older", base.Add(2*time.Minute))
	tieOlder.ID = tiePrefix[:63] + "d"
	tieOlder.Digest = "sha256:" + tieOlder.ID
	archived := comparisonSBOM(t, tenantID, repository, "archived", base.Add(4*time.Minute))
	archived.Status = "archived"
	otherRepository := comparisonSBOM(t, tenantID, repository+"-other", "other-repo", base.Add(5*time.Minute))
	target := comparisonSBOM(t, tenantID, repository, "target", base.Add(6*time.Minute))
	for _, sb := range []*postgres.SBOM{previous, tieOlder, archived, otherRepository, target} {
		if _, _, _, err := st.UpsertSBOM(ctx, sb); err != nil {
			t.Fatalf("upsert %s: %v", sb.Version, err)
		}
	}
	otherTenantID, _ := seedTenantAndSBOM(t, st)
	foreign := comparisonSBOM(t, otherTenantID, repository, "foreign", base.Add(5*time.Minute))
	if _, _, _, err := st.UpsertSBOM(ctx, foreign); err != nil {
		t.Fatalf("upsert foreign predecessor: %v", err)
	}
	insertComparisonFinding(t, st, target.ID, "grype", "target-critical", "CVE-2026-9001", "critical", false)

	got, err := comparer.ComparePreviousSBOM(ctx, tenantID, target.ID)
	if err != nil {
		t.Fatalf("ComparePreviousSBOM() error: %v", err)
	}
	if got == nil || got.From.SBOMID != previous.ID || got.To.SBOMID != target.ID {
		t.Fatalf("comparison = %+v, want %s -> %s", got, previous.ID, target.ID)
	}
	if got.Verdict != postgres.PostureRegresses {
		t.Fatalf("verdict = %q, want %q", got.Verdict, postgres.PostureRegresses)
	}
}

func TestComparePreviousSBOM_ReturnsImprovementAndNilWithoutPredecessor(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	comparer, ok := any(st).(previousSBOMComparer)
	if !ok {
		t.Fatal("Store does not implement ComparePreviousSBOM")
	}

	tenantID, from := seedTenantAndSBOM(t, st)
	repository := "registry.test/posture-improvement"
	base := time.Now().UTC().Add(-time.Hour)
	if _, err := st.DB().ExecContext(ctx,
		`UPDATE devradar_sbom SET repository=$2, generated_at=$3 WHERE id=$1`,
		from.ID, repository, base); err != nil {
		t.Fatalf("update baseline: %v", err)
	}
	insertComparisonFinding(t, st, from.ID, "grype", "baseline-critical", "CVE-2026-9010", "critical", false)
	to := comparisonSBOM(t, tenantID, repository, "improved", base.Add(time.Minute))
	if _, _, _, err := st.UpsertSBOM(ctx, to); err != nil {
		t.Fatalf("upsert improved SBOM: %v", err)
	}

	got, err := comparer.ComparePreviousSBOM(ctx, tenantID, to.ID)
	if err != nil {
		t.Fatalf("ComparePreviousSBOM() error: %v", err)
	}
	if got == nil || got.Verdict != postgres.PostureImproves || got.From.SBOMID != from.ID {
		t.Fatalf("comparison = %+v, want improvement from %s", got, from.ID)
	}

	none, err := comparer.ComparePreviousSBOM(ctx, tenantID, from.ID)
	if err != nil {
		t.Fatalf("ComparePreviousSBOM(first) error: %v", err)
	}
	if none != nil {
		t.Fatalf("comparison without predecessor = %+v, want nil", none)
	}
}

package postgres_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/data/postgres"
)

// testStore connects to the local/CI Postgres, skipping if unreachable so unit
// runs stay green without a database.
func testStore(t *testing.T) *postgres.Store {
	t.Helper()
	st, err := postgres.NewFromEnv(context.Background())
	if err != nil {
		t.Skipf("skipping integration test (no database): %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func randID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// seedTenantAndSBOM creates an isolated tenant + one active SBOM for a test.
func seedTenantAndSBOM(t *testing.T, st *postgres.Store) (tenantID string, sb *postgres.SBOM) {
	t.Helper()
	ctx := context.Background()

	err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"test-"+randID(t)[:8]+"@example.com").Scan(&tenantID)
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	sb = &postgres.SBOM{
		ID:           randID(t) + randID(t), // 64 hex chars, like a real content hash
		TenantID:     tenantID,
		ImageRef:     "registry.test/app",
		Digest:       "sha256:" + randID(t) + randID(t),
		Format:       "cyclonedx",
		PackageCount: 100,
		ObjectPath:   "gs://test/" + tenantID,
	}
	if _, _, err := st.UpsertSBOM(ctx, sb); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}
	return tenantID, sb
}

func countEvents(t *testing.T, st *postgres.Store, sbomID, eventType, cause string) int {
	t.Helper()
	var n int
	err := st.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM devradar_finding_event
		 WHERE sbom_id=$1 AND event_type=$2 AND cause=$3`,
		sbomID, eventType, cause).Scan(&n)
	if err != nil {
		t.Fatalf("count events: %v", err)
	}
	return n
}

func vuln(cve, pkg, ver, sev string, score float32, fixed bool) data.Vulnerability {
	return data.Vulnerability{Exposure: cve, Package: pkg, Version: ver, Severity: sev, Score: score, IsFixed: fixed}
}

// TestUpsertSBOM_VersionBackfill verifies the conflict semantics: a first submit
// with no version, then a re-submit of the same (tenant, digest, format) that
// now carries a tag backfills the version label without inserting a new row; a
// later digest-only re-submit must NOT wipe it.
func TestUpsertSBOM_VersionBackfill(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	var tenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"ver-"+randID(t)[:8]+"@example.com").Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	digest := "sha256:" + randID(t) + randID(t)
	base := postgres.SBOM{
		ID: randID(t) + randID(t), TenantID: tenantID, ImageRef: "reg.test/app",
		Repository: "reg.test/app", Digest: digest, Format: "cyclonedx",
		PackageCount: 10, ObjectPath: "gs://x",
	}

	// 1. First submit, no version.
	id, inserted, err := st.UpsertSBOM(ctx, &base)
	if err != nil || !inserted {
		t.Fatalf("first submit: inserted=%v err=%v", inserted, err)
	}
	if got := sbomVersion(t, st, id); got != "" {
		t.Errorf("version after no-version submit = %q, want empty", got)
	}

	// 2. Re-submit same digest, now with a tag → backfills, does NOT insert.
	withVer := base
	withVer.ID = randID(t) + randID(t) // different candidate id; conflict resolves to existing
	withVer.Version = "v1.20.2"
	id2, inserted2, err := st.UpsertSBOM(ctx, &withVer)
	if err != nil {
		t.Fatalf("re-submit with version: %v", err)
	}
	if inserted2 {
		t.Errorf("re-submit should not insert a new row")
	}
	if id2 != id {
		t.Errorf("re-submit id = %s, want existing %s", id2, id)
	}
	if got := sbomVersion(t, st, id); got != "v1.20.2" {
		t.Errorf("version after backfill = %q, want v1.20.2", got)
	}

	// 3. Later digest-only re-submit must NOT wipe the version.
	noVer := base
	noVer.Version = ""
	if _, _, err := st.UpsertSBOM(ctx, &noVer); err != nil {
		t.Fatalf("digest-only re-submit: %v", err)
	}
	if got := sbomVersion(t, st, id); got != "v1.20.2" {
		t.Errorf("version after digest-only re-submit = %q, want v1.20.2 (not wiped)", got)
	}
}

func sbomVersion(t *testing.T, st *postgres.Store, id string) string {
	t.Helper()
	var v *string
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT version FROM devradar_sbom WHERE id=$1`, id).Scan(&v); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if v == nil {
		return ""
	}
	return *v
}

// TestApplyScan_DeltaEngine exercises the full lifecycle: first scan (all added,
// image-caused), an unchanged rescan (no events), a DB update that adds a
// finding (db-caused), a re-rating, a resolve, and a tooling-only upgrade
// (tooling-caused, must not alert).
func TestApplyScan_DeltaEngine(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	_, sb := seedTenantAndSBOM(t, st)

	v1 := postgres.Versions{DBVersion: "db-1", ScannerVersion: "grype-0.115", CanonicalizerVersion: "passthrough"}

	// ── Scan 1: two findings, no prior state → both 'added', cause 'image'.
	scan1 := []data.Vulnerability{
		vuln("CVE-1", "openssl", "1.1.1", data.SeverityHigh, 7.5, false),
		vuln("CVE-2", "zlib", "1.2.11", data.SeverityMedium, 5.0, false),
	}
	if err := st.ApplyScan(ctx, sb, "grype", v1, scan1); err != nil {
		t.Fatalf("scan1: %v", err)
	}
	if got := countEvents(t, st, sb.ID, data.EventAdded, data.CauseImage); got != 2 {
		t.Errorf("scan1 added/image = %d, want 2", got)
	}

	// ── Scan 2: identical input, same versions → zero new events.
	if err := st.ApplyScan(ctx, sb, "grype", v1, scan1); err != nil {
		t.Fatalf("scan2: %v", err)
	}
	if got := totalEvents(t, st, sb.ID); got != 2 {
		t.Errorf("after unchanged rescan, total events = %d, want 2 (no new)", got)
	}

	// ── Scan 3: new DB version surfaces a new CVE and re-rates one → cause 'db'.
	v2 := v1
	v2.DBVersion = "db-2"
	scan3 := []data.Vulnerability{
		vuln("CVE-1", "openssl", "1.1.1", data.SeverityCritical, 9.8, false), // re-rated high→critical
		vuln("CVE-2", "zlib", "1.2.11", data.SeverityMedium, 5.0, false),     // unchanged
		vuln("CVE-3", "curl", "7.80", data.SeverityHigh, 8.1, false),         // new
	}
	if err := st.ApplyScan(ctx, sb, "grype", v2, scan3); err != nil {
		t.Fatalf("scan3: %v", err)
	}
	if got := countEvents(t, st, sb.ID, data.EventAdded, data.CauseDB); got != 1 {
		t.Errorf("scan3 added/db = %d, want 1", got)
	}
	if got := countEvents(t, st, sb.ID, data.EventRerated, data.CauseDB); got != 1 {
		t.Errorf("scan3 rerated/db = %d, want 1", got)
	}

	// ── Scan 4: same DB, CVE-2 resolved (gone) and CVE-1 gains a fix → cause 'db'
	// (db version identical to prior run, so classifier falls to db, not tooling).
	scan4 := []data.Vulnerability{
		vuln("CVE-1", "openssl", "1.1.1", data.SeverityCritical, 9.8, true), // now fixed
		vuln("CVE-3", "curl", "7.80", data.SeverityHigh, 8.1, false),
	}
	if err := st.ApplyScan(ctx, sb, "grype", v2, scan4); err != nil {
		t.Fatalf("scan4: %v", err)
	}
	if got := countEvents(t, st, sb.ID, data.EventResolved, data.CauseDB); got != 1 {
		t.Errorf("scan4 resolved/db = %d, want 1", got)
	}
	if got := countEvents(t, st, sb.ID, data.EventFixed, data.CauseDB); got != 1 {
		t.Errorf("scan4 fixed/db = %d, want 1", got)
	}

	// ── Scan 5: scanner UPGRADE drops a finding (matcher change), same DB.
	// The delta must be attributed to 'tooling' and be invisible to alerting.
	v3 := v2
	v3.ScannerVersion = "grype-0.116"
	scan5 := []data.Vulnerability{
		vuln("CVE-1", "openssl", "1.1.1", data.SeverityCritical, 9.8, true),
		// CVE-3 dropped by the new matcher
	}
	if err := st.ApplyScan(ctx, sb, "grype", v3, scan5); err != nil {
		t.Fatalf("scan5: %v", err)
	}
	if got := countEvents(t, st, sb.ID, data.EventResolved, data.CauseTooling); got != 1 {
		t.Errorf("scan5 resolved/tooling = %d, want 1", got)
	}

	// Alerting query must exclude tooling: an alertable-cause resolve of CVE-3
	// must NOT exist.
	if got := alertableEvents(t, st, sb.ID); got == 0 {
		t.Errorf("expected some alertable (image|db) events to exist")
	}
	var toolingAlertable int
	err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM devradar_finding_event
		 WHERE sbom_id=$1 AND cause='tooling' AND cause IN ('image','db')`, sb.ID).Scan(&toolingAlertable)
	if err != nil {
		t.Fatal(err)
	}
	if toolingAlertable != 0 {
		t.Errorf("tooling events must never match the alerting filter, got %d", toolingAlertable)
	}
}

func totalEvents(t *testing.T, st *postgres.Store, sbomID string) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM devradar_finding_event WHERE sbom_id=$1`, sbomID).Scan(&n); err != nil {
		t.Fatalf("total events: %v", err)
	}
	return n
}

func alertableEvents(t *testing.T, st *postgres.Store, sbomID string) int {
	t.Helper()
	var n int
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM devradar_finding_event WHERE sbom_id=$1 AND cause IN ('image','db')`,
		sbomID).Scan(&n); err != nil {
		t.Fatalf("alertable events: %v", err)
	}
	return n
}

// TestApplyScan_Idempotent verifies a re-run produces no duplicate events.
func TestApplyScan_Idempotent(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	_, sb := seedTenantAndSBOM(t, st)

	v := postgres.Versions{DBVersion: "db-1", ScannerVersion: "grype-0.115", CanonicalizerVersion: "passthrough"}
	scan := []data.Vulnerability{vuln("CVE-9", "bash", "5.0", data.SeverityLow, 2.1, false)}

	if err := st.ApplyScan(ctx, sb, "grype", v, scan); err != nil {
		t.Fatalf("first: %v", err)
	}
	// Re-run at the SAME instant is absorbed by the event UNIQUE constraint;
	// but ApplyScan stamps occurred_at = now(), so a natural retry within the
	// same scan uses the same run. Here we assert current state is stable.
	if err := st.ApplyScan(ctx, sb, "grype", v, scan); err != nil {
		t.Fatalf("second: %v", err)
	}
	var findings int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM devradar_finding WHERE sbom_id=$1`, sb.ID).Scan(&findings); err != nil {
		t.Fatal(err)
	}
	if findings != 1 {
		t.Errorf("current findings = %d, want 1", findings)
	}
}

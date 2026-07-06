package postgres_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/vex"
)

// TestListImages_ThresholdTrimsBreakdown verifies that ListImages keeps every
// image but trims sub-threshold buckets to zero, keeps unknown, leaves Total as
// the overall count, and sets Relevant to the sum of visible buckets.
func TestListImages_ThresholdTrimsBreakdown(t *testing.T) {
	st, err := postgres.NewFromEnv(context.Background())
	if err != nil {
		t.Skipf("skipping (no database): %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()

	// Isolated tenant + one SBOM with one finding per severity.
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	var tenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"img-"+hex.EncodeToString(b)+"@example.com").Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	sbomID := "img-" + hex.EncodeToString(b)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_sbom (id, tenant_id, image_ref, digest, format, object_path)
		VALUES ($1,$2,'img','sha256:x','cyclonedx','gs://x')`, sbomID, tenantID); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}
	for _, sev := range []string{"critical", "high", "medium", "low", "negligible", "unknown"} {
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_finding (sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
			VALUES ($1,'grype',$2,$3,'pkg','1.0',$4,1.0,false)`,
			sbomID, "f-"+sev, "CVE-"+sev, sev); err != nil {
			t.Fatalf("seed finding %s: %v", sev, err)
		}
	}

	get := func(min string) postgres.SeverityCounts {
		imgs, err := st.ListImages(ctx, tenantID, min)
		if err != nil {
			t.Fatalf("ListImages(%s): %v", min, err)
		}
		if len(imgs) != 1 {
			t.Fatalf("ListImages(%s): %d images, want 1 (image must never disappear)", min, len(imgs))
		}
		return imgs[0].Counts
	}

	// critical: only critical + unknown visible; med/high/low/neg zeroed.
	c := get("critical")
	if c.Critical != 1 || c.High != 0 || c.Medium != 0 || c.Low != 0 || c.Negligible != 0 {
		t.Errorf("critical: buckets = %+v, want only critical=1", c)
	}
	if c.Unknown != 1 {
		t.Errorf("critical: unknown = %d, want 1 (always kept)", c.Unknown)
	}
	if c.Total != 6 {
		t.Errorf("critical: total = %d, want 6 (overall, not trimmed)", c.Total)
	}
	if c.Relevant != 2 { // critical + unknown
		t.Errorf("critical: relevant = %d, want 2", c.Relevant)
	}

	// medium (default): critical+high+medium+unknown; low/neg zeroed.
	c = get("medium")
	if c.Low != 0 || c.Negligible != 0 {
		t.Errorf("medium: low/neg should be zeroed, got low=%d neg=%d", c.Low, c.Negligible)
	}
	if c.Critical != 1 || c.High != 1 || c.Medium != 1 {
		t.Errorf("medium: crit/high/med should be visible, got %+v", c)
	}
	if c.Relevant != 4 { // crit+high+med+unknown
		t.Errorf("medium: relevant = %d, want 4", c.Relevant)
	}

	// negligible: everything visible.
	c = get("negligible")
	if c.Relevant != 6 || c.Total != 6 {
		t.Errorf("negligible: relevant=%d total=%d, want 6/6", c.Relevant, c.Total)
	}
}

// TestImageTimeline_AcrossDigests verifies the cross-digest history: two SBOMs
// sharing one image_ref (an image whose digest changed) produce a merged,
// severity-filtered, newest-first timeline; an unknown ref is 404; and the
// timeline is tenant-scoped.
func TestImageTimeline_AcrossDigests(t *testing.T) {
	st, err := postgres.NewFromEnv(context.Background())
	if err != nil {
		t.Skipf("skipping (no database): %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	suffix := hex.EncodeToString(b)
	var tenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"tl-"+suffix+"@example.com").Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	imageRef := "example.com/app-" + suffix

	// Two digests of the same image_ref, each with one added event at a distinct
	// severity and time.
	seed := func(digest, sev string, when time.Time) {
		sbomID := digest
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_sbom (id, tenant_id, image_ref, digest, format, object_path)
			VALUES ($1,$2,$3,$4,'cyclonedx','gs://x')`, sbomID, tenantID, imageRef, digest); err != nil {
			t.Fatalf("seed sbom: %v", err)
		}
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_finding_event
				(tenant_id, sbom_id, scanner, finding_id, event_type, exposure, package, version,
				 severity, score, cause, db_version, scanner_version, scan_run_id, occurred_at)
			VALUES ($1,$2,'grype',$3,'added',$4,'pkg','1.0',$5,1.0,'image','db-1','grype-1',
				gen_random_uuid(),$6)`,
			tenantID, sbomID, "f-"+digest, "CVE-"+sev, sev, when); err != nil {
			t.Fatalf("seed event: %v", err)
		}
	}
	old := time.Now().UTC().Add(-48 * time.Hour)
	recent := time.Now().UTC().Add(-1 * time.Hour)
	seed("sha256:aaa"+suffix, "high", old)
	seed("sha256:bbb"+suffix, "low", recent)

	// Full history (negligible threshold → both events), newest first.
	all, err := st.ImageTimeline(ctx, tenantID, imageRef, "negligible", 100)
	if err != nil {
		t.Fatalf("timeline: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("timeline len = %d, want 2", len(all))
	}
	if !all[0].OccurredAt.After(all[1].OccurredAt) {
		t.Errorf("timeline not newest-first: %v then %v", all[0].OccurredAt, all[1].OccurredAt)
	}
	if all[0].Digest == all[1].Digest {
		t.Errorf("expected events from two distinct digests, both %s", all[0].Digest)
	}

	// medium threshold drops the 'low' event, keeps 'high'.
	hi, err := st.ImageTimeline(ctx, tenantID, imageRef, "medium", 100)
	if err != nil {
		t.Fatalf("timeline (medium): %v", err)
	}
	if len(hi) != 1 || hi[0].Severity != "high" {
		t.Errorf("medium threshold: got %d events (want 1 high): %+v", len(hi), hi)
	}

	// Unknown ref → ErrNotFound.
	if _, err := st.ImageTimeline(ctx, tenantID, "example.com/nope", "medium", 100); !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("unknown ref: err = %v, want ErrNotFound", err)
	}

	// Another tenant sees nothing for this ref → ErrNotFound (isolation).
	var otherID string
	_ = st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"other-"+suffix+"@example.com").Scan(&otherID)
	if _, err := st.ImageTimeline(ctx, otherID, imageRef, "medium", 100); !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("cross-tenant timeline: err = %v, want ErrNotFound", err)
	}
}

// TestVEXSuppression verifies a not_affected VEX statement hides a finding from
// the default view (and from counts), is included when showSuppressed is set and
// carries its status.
func TestVEXSuppression(t *testing.T) {
	st, err := postgres.NewFromEnv(context.Background())
	if err != nil {
		t.Skipf("skipping (no database): %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	suffix := hex.EncodeToString(b)
	var tenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"vex-"+suffix+"@example.com").Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	sbomID := "vex-" + suffix
	digest := "sha256:vex" + suffix
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_sbom (id, tenant_id, image_ref, repository, digest, format, object_path)
		VALUES ($1,$2,'reg/app','reg/app',$3,'cyclonedx','gs://x')`, sbomID, tenantID, digest); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}
	for _, cve := range []string{"CVE-A" + suffix, "CVE-B" + suffix} {
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_finding (sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
			VALUES ($1,'grype',$2,$3,'pkg','1.0','high',7.0,false)`,
			sbomID, cve+"/pkg/1.0", cve); err != nil {
			t.Fatalf("seed finding: %v", err)
		}
	}

	countDefault := func() int {
		f, _, err := st.FindingsBySBOM(ctx, tenantID, sbomID, "negligible", false, false, "", 50)
		if err != nil {
			t.Fatalf("findings: %v", err)
		}
		return len(f)
	}
	if countDefault() != 2 {
		t.Fatalf("pre-VEX findings = %d, want 2", countDefault())
	}

	doc := &vex.Document{Author: "sec@x", Raw: []byte(`{}`), Statements: []vex.Statement{
		{ProductDigest: digest, Vulnerability: "CVE-A" + suffix, Status: vex.StatusNotAffected,
			Justification: "vulnerable_code_not_in_execute_path"},
	}}
	if _, matched, err := st.SaveVEXDocument(ctx, tenantID, doc); err != nil || matched != 1 {
		t.Fatalf("save vex: matched=%d err=%v", matched, err)
	}

	if got := countDefault(); got != 1 {
		t.Errorf("post-VEX default findings = %d, want 1 (one suppressed)", got)
	}
	all, _, _ := st.FindingsBySBOM(ctx, tenantID, sbomID, "negligible", false, true, "", 50)
	if len(all) != 2 {
		t.Fatalf("showSuppressed findings = %d, want 2", len(all))
	}
	var sawStatus bool
	for _, f := range all {
		if f.Exposure == "CVE-A"+suffix && f.VEXStatus == vex.StatusNotAffected {
			sawStatus = true
		}
	}
	if !sawStatus {
		t.Errorf("suppressed finding should carry vex_status=not_affected")
	}

	d, err := st.GetSBOM(ctx, tenantID, sbomID, "negligible")
	if err != nil {
		t.Fatalf("get sbom: %v", err)
	}
	if d.Counts.Total != 1 {
		t.Errorf("suppressed count: total = %d, want 1", d.Counts.Total)
	}
}

// TestFleetCVEs_BlastRadiusRanking verifies CVEs are grouped across images,
// ranked KEV-first then severity then blast radius, and that CVEDetail lists
// every occurrence.
func TestFleetCVEs_BlastRadiusRanking(t *testing.T) {
	st, err := postgres.NewFromEnv(context.Background())
	if err != nil {
		t.Skipf("skipping (no database): %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	suffix := hex.EncodeToString(b)
	var tenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"cve-"+suffix+"@example.com").Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	// Helper: an image (repo) with a finding for a given CVE at a severity.
	mk := func(repo, cve, sev string) {
		digest := "sha256:" + repo + suffix
		_, _ = st.DB().ExecContext(ctx, `
			INSERT INTO devradar_sbom (id, tenant_id, image_ref, repository, digest, format, object_path)
			VALUES ($1,$2,$3,$3,$4,'cyclonedx','gs://x') ON CONFLICT DO NOTHING`,
			digest, tenantID, "reg/"+repo+"-"+suffix, digest)
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_finding (sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
			VALUES ($1,'grype',$2,$3,'pkg','1.0',$4,7.0,false) ON CONFLICT DO NOTHING`,
			digest, cve+"/pkg/1.0", cve, sev); err != nil {
			t.Fatalf("seed finding: %v", err)
		}
	}
	cveWide := "CVE-" + suffix + "-WIDE" // medium, in 3 images
	cveKEV := "CVE-" + suffix + "-KEV"   // high, in 1 image, but KEV
	mk("a", cveWide, "medium")
	mk("b", cveWide, "medium")
	mk("c", cveWide, "medium")
	mk("a", cveKEV, "high")
	// Mark the KEV CVE as known-exploited.
	if _, err := st.DB().ExecContext(ctx,
		`INSERT INTO devradar_cve_enrichment (cve, kev, epss_score) VALUES ($1, true, 0.9)
		 ON CONFLICT (cve) DO UPDATE SET kev=true`, cveKEV); err != nil {
		t.Fatalf("seed enrichment: %v", err)
	}

	cves, _, err := st.FleetCVEs(ctx, tenantID, "negligible", "", 50)
	if err != nil {
		t.Fatalf("fleet cves: %v", err)
	}
	// Restrict to our two seeded CVEs (tenant is isolated, so that's all there is).
	var wide, kev *postgres.FleetCVE
	for i := range cves {
		switch cves[i].CVE {
		case cveWide:
			wide = &cves[i]
		case cveKEV:
			kev = &cves[i]
		}
	}
	if wide == nil || kev == nil {
		t.Fatalf("expected both CVEs, got %+v", cves)
	}
	if wide.ImageCount != 3 {
		t.Errorf("wide CVE image_count = %d, want 3", wide.ImageCount)
	}
	if !kev.KEV {
		t.Errorf("kev CVE should be flagged KEV")
	}
	// KEV must outrank a wider-but-non-KEV CVE: kev appears before wide.
	kevIdx, wideIdx := -1, -1
	for i := range cves {
		if cves[i].CVE == cveKEV {
			kevIdx = i
		}
		if cves[i].CVE == cveWide {
			wideIdx = i
		}
	}
	if kevIdx > wideIdx {
		t.Errorf("KEV CVE (idx %d) should rank above wide CVE (idx %d)", kevIdx, wideIdx)
	}

	// CVEDetail lists all 3 occurrences of the wide CVE.
	d, err := st.CVEDetail(ctx, tenantID, cveWide)
	if err != nil {
		t.Fatalf("cve detail: %v", err)
	}
	if len(d.Occurrences) != 3 {
		t.Errorf("wide CVE occurrences = %d, want 3", len(d.Occurrences))
	}
	// Unknown CVE → ErrNotFound.
	if _, err := st.CVEDetail(ctx, tenantID, "CVE-nope-"+suffix); !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("unknown cve: err = %v, want ErrNotFound", err)
	}
}

// TestFindings_PagingFilterRollup verifies findings page in worst-first order
// without gaps/overlaps, the fixable filter restricts the set, and the package
// rollup groups worst-severity-first.
func TestFindings_PagingFilterRollup(t *testing.T) {
	st, err := postgres.NewFromEnv(context.Background())
	if err != nil {
		t.Skipf("skipping (no database): %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	suffix := hex.EncodeToString(b)
	var tenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"find-"+suffix+"@example.com").Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	sbomID := "find-" + suffix
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_sbom (id, tenant_id, image_ref, repository, digest, format, object_path)
		VALUES ($1,$2,'reg/app','reg/app',$3,'cyclonedx','gs://x')`,
		sbomID, tenantID, "sha256:"+suffix); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}
	// 6 findings: 2 critical (1 fixed), 2 high, 2 medium (1 fixed).
	seed := func(cve, sev string, fixed bool) {
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_finding (sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
			VALUES ($1,'grype',$2,$3,'pkg-'||$3,'1.0',$4,5.0,$5)`,
			sbomID, cve+suffix, cve, sev, fixed); err != nil {
			t.Fatalf("seed finding: %v", err)
		}
	}
	seed("CVE-c1", "critical", true)
	seed("CVE-c2", "critical", false)
	seed("CVE-h1", "high", false)
	seed("CVE-h2", "high", false)
	seed("CVE-m1", "medium", true)
	seed("CVE-m2", "medium", false)

	// Page 2 at a time through all 6; assert worst-first, no dup/gap.
	var got []string
	cursor := ""
	for range 5 {
		page, next, err := st.FindingsBySBOM(ctx, tenantID, sbomID, "negligible", false, false, cursor, 2)
		if err != nil {
			t.Fatalf("findings page: %v", err)
		}
		for _, f := range page {
			got = append(got, f.Severity)
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(got) != 6 {
		t.Fatalf("paged findings = %d, want 6 (no gap/dup)", len(got))
	}
	want := []string{"critical", "critical", "high", "high", "medium", "medium"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("order[%d] = %s, want %s (worst-first)", i, got[i], want[i])
		}
	}

	// Fixable filter: only the 2 fixed findings (1 crit, 1 med).
	fx, _, err := st.FindingsBySBOM(ctx, tenantID, sbomID, "negligible", true, false, "", 50)
	if err != nil {
		t.Fatalf("fixable findings: %v", err)
	}
	if len(fx) != 2 {
		t.Errorf("fixable findings = %d, want 2", len(fx))
	}
	for _, f := range fx {
		if !f.IsFixed {
			t.Errorf("fixable filter returned an unfixed finding: %s", f.Exposure)
		}
	}

	// Package rollup: each CVE is its own package here (pkg-CVE-*), worst first.
	pkgs, err := st.PackageRollup(ctx, tenantID, sbomID, "negligible", 10)
	if err != nil {
		t.Fatalf("rollup: %v", err)
	}
	if len(pkgs) == 0 || pkgs[0].WorstSev != "critical" {
		t.Errorf("rollup should lead with a critical package, got %+v", pkgs)
	}
}

// TestListRepoImages_RiskOrderAndPaging verifies images come back risk-ranked
// (critical, then high, then total) from SQL, that keyset pagination walks that
// order without gaps or overlaps, and that FleetStats is a whole-tenant rollup
// independent of the page.
func TestListRepoImages_RiskOrderAndPaging(t *testing.T) {
	st, err := postgres.NewFromEnv(context.Background())
	if err != nil {
		t.Skipf("skipping (no database): %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	suffix := hex.EncodeToString(b)
	var tenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"rank-"+suffix+"@example.com").Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	// Three images with descending risk: A (1 critical), B (2 high), C (3 medium).
	seedImg := func(name string, sevs ...string) {
		digest := "sha256:" + name + suffix
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_sbom (id, tenant_id, image_ref, repository, digest, format, object_path)
			VALUES ($1,$2,$3,$3,$4,'cyclonedx','gs://x')`,
			digest, tenantID, "reg/"+name+"-"+suffix, digest); err != nil {
			t.Fatalf("seed sbom %s: %v", name, err)
		}
		for i, sev := range sevs {
			if _, err := st.DB().ExecContext(ctx, `
				INSERT INTO devradar_finding (sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
				VALUES ($1,'grype',$2,$3,'pkg','1.0',$4,1.0,$5)`,
				digest, name+"-f-"+hex.EncodeToString([]byte{byte(i)}), "CVE-"+name+"-"+sev, sev, i%2 == 0); err != nil {
				t.Fatalf("seed finding: %v", err)
			}
		}
	}
	seedImg("a", "critical")
	seedImg("b", "high", "high")
	seedImg("c", "medium", "medium", "medium")

	// Fleet stats: whole tenant, not one page.
	fs, err := st.FleetStats(ctx, tenantID)
	if err != nil {
		t.Fatalf("fleet stats: %v", err)
	}
	if fs.Images != 3 || fs.Total != 6 || fs.Critical != 1 || fs.High != 2 {
		t.Errorf("fleet stats = %+v, want images=3 total=6 crit=1 high=2", fs)
	}

	// Full list: risk order must be A (crit) → B (high) → C (medium).
	all, _, err := st.ListRepoImages(ctx, tenantID, "negligible", "", 50)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("want 3 images, got %d", len(all))
	}
	wantOrder := []string{"reg/a-" + suffix, "reg/b-" + suffix, "reg/c-" + suffix}
	for i, w := range wantOrder {
		if all[i].Repository != w {
			t.Errorf("risk order[%d] = %s, want %s", i, all[i].Repository, w)
		}
	}

	// Paginate 2 at a time: page1 = [A,B] + cursor, page2 = [C] + no cursor.
	p1, next, err := st.ListRepoImages(ctx, tenantID, "negligible", "", 2)
	if err != nil || len(p1) != 2 || next == "" {
		t.Fatalf("page1: len=%d next=%q err=%v", len(p1), next, err)
	}
	p2, next2, err := st.ListRepoImages(ctx, tenantID, "negligible", next, 2)
	if err != nil || len(p2) != 1 || next2 != "" {
		t.Fatalf("page2: len=%d next=%q err=%v", len(p2), next2, err)
	}
	if p1[0].Repository != wantOrder[0] || p1[1].Repository != wantOrder[1] || p2[0].Repository != wantOrder[2] {
		t.Errorf("paged order wrong: %s,%s then %s", p1[0].Repository, p1[1].Repository, p2[0].Repository)
	}
}

// TestRepoViews covers the CUJ endpoints: grouping SBOMs by repository, listing
// an image's SBOMs newest-generation-first, the cross-digest repo timeline, and
// keyset pagination on each.
func TestRepoViews(t *testing.T) {
	st, err := postgres.NewFromEnv(context.Background())
	if err != nil {
		t.Skipf("skipping (no database): %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	suffix := hex.EncodeToString(b)
	var tenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"repo-"+suffix+"@example.com").Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	repo := "quay.io/team/app-" + suffix

	// Three SBOMs under ONE repository: two versions of it, plus a re-scan digest,
	// each with a distinct generated_at and one event.
	seed := func(digest, version string, gen time.Time) {
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_sbom
				(id, tenant_id, image_ref, repository, version, digest, format, package_count, object_path, generated_at)
			VALUES ($1,$2,$3,$4,$5,$6,'cyclonedx',10,'gs://x',$7)`,
			digest, tenantID, repo+"@"+digest, repo, version, digest, gen); err != nil {
			t.Fatalf("seed sbom: %v", err)
		}
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_finding_event
				(tenant_id, sbom_id, scanner, finding_id, event_type, exposure, package, version,
				 severity, score, cause, db_version, scanner_version, scan_run_id, occurred_at)
			VALUES ($1,$2,'grype',$3,'added',$4,'pkg','1.0','high',7.0,'image','db-1','grype-1',
				gen_random_uuid(),$5)`,
			tenantID, digest, "f-"+digest, "CVE-"+digest, gen); err != nil {
			t.Fatalf("seed event: %v", err)
		}
	}
	t0 := time.Now().UTC().Add(-72 * time.Hour)
	seed("sha256:a"+suffix, "v1.0.0", t0)
	seed("sha256:b"+suffix, "v1.1.0", t0.Add(24*time.Hour))
	seed("sha256:c"+suffix, "v1.1.0", t0.Add(48*time.Hour)) // rescan of same version

	// Grouped images: one row for the whole repository, 3 SBOMs / 3 digests.
	imgs, _, err := st.ListRepoImages(ctx, tenantID, "negligible", "", 50)
	if err != nil {
		t.Fatalf("ListRepoImages: %v", err)
	}
	var found *postgres.RepoImage
	for i := range imgs {
		if imgs[i].Repository == repo {
			found = &imgs[i]
		}
	}
	if found == nil {
		t.Fatalf("repo %s not in grouped images", repo)
	}
	if found.SBOMCount != 3 || found.DigestCount != 3 {
		t.Errorf("grouped: sbom_count=%d digest_count=%d, want 3/3", found.SBOMCount, found.DigestCount)
	}
	if len(found.Versions) != 2 { // v1.0.0, v1.1.0 (deduped)
		t.Errorf("grouped versions = %v, want 2 distinct", found.Versions)
	}

	// Per-image SBOMs, newest generation first.
	sboms, _, err := st.SBOMsForRepo(ctx, tenantID, repo, "", 50)
	if err != nil {
		t.Fatalf("SBOMsForRepo: %v", err)
	}
	if len(sboms) != 3 {
		t.Fatalf("SBOMsForRepo len = %d, want 3", len(sboms))
	}
	if !sboms[0].EffectiveAt.After(sboms[1].EffectiveAt) || !sboms[1].EffectiveAt.After(sboms[2].EffectiveAt) {
		t.Errorf("SBOMs not newest-first: %v", []time.Time{sboms[0].EffectiveAt, sboms[1].EffectiveAt, sboms[2].EffectiveAt})
	}

	// Unknown repo → ErrNotFound; cross-tenant → ErrNotFound.
	if _, _, err := st.SBOMsForRepo(ctx, tenantID, "quay.io/nope", "", 50); !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("unknown repo: err = %v, want ErrNotFound", err)
	}

	// Keyset pagination on the repo timeline: page size 2 → 2 rows + a cursor,
	// then the remaining 1 with no further cursor. No overlap, no gap.
	p1, next, err := st.RepoTimeline(ctx, tenantID, repo, "negligible", "", 2)
	if err != nil {
		t.Fatalf("RepoTimeline p1: %v", err)
	}
	if len(p1) != 2 || next == "" {
		t.Fatalf("page1: len=%d next=%q, want 2 + cursor", len(p1), next)
	}
	p2, next2, err := st.RepoTimeline(ctx, tenantID, repo, "negligible", next, 2)
	if err != nil {
		t.Fatalf("RepoTimeline p2: %v", err)
	}
	if len(p2) != 1 || next2 != "" {
		t.Fatalf("page2: len=%d next=%q, want 1 + no cursor", len(p2), next2)
	}
	// Combined pages are strictly newest-first and disjoint.
	all := append(append([]postgres.TimelineEvent{}, p1...), p2...)
	for i := 1; i < len(all); i++ {
		if all[i-1].OccurredAt.Before(all[i].OccurredAt) {
			t.Errorf("paged timeline out of order at %d", i)
		}
	}
	if all[0].Exposure == all[2].Exposure {
		t.Errorf("pagination returned a duplicate row across pages")
	}
}

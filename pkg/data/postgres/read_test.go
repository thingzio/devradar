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
	st := testStore(t)
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
	// These tests seed devradar_finding directly (bypassing ApplyScan), so build
	// the derived rollup the read path reads from.
	if err := st.RecomputeSBOMRollup(ctx, sbomID); err != nil {
		t.Fatalf("recompute rollup: %v", err)
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

// TestListImages_DedupsAcrossScanners verifies a CVE reported by BOTH grype and
// trivy (two devradar_finding rows sharing one finding_id) counts ONCE, not
// twice — the fleet/image rollups count distinct finding_id, not raw rows.
func TestListImages_DedupsAcrossScanners(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	var tenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"dup-"+hex.EncodeToString(b)+"@example.com").Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	sbomID := "dup-" + hex.EncodeToString(b)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_sbom (id, tenant_id, image_ref, digest, format, object_path)
		VALUES ($1,$2,'img','sha256:dup','cyclonedx','gs://x')`, sbomID, tenantID); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}
	// Same finding_id under two scanners = one real CVE seen twice.
	for _, sc := range []string{"grype", "trivy"} {
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_finding (sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
			VALUES ($1,$2,'shared-fid','CVE-DUP','pkg','1.0','critical',9.8,false)`,
			sbomID, sc); err != nil {
			t.Fatalf("seed finding %s: %v", sc, err)
		}
	}
	if err := st.RecomputeSBOMRollup(ctx, sbomID); err != nil {
		t.Fatalf("recompute rollup: %v", err)
	}

	imgs, err := st.ListImages(ctx, tenantID, "low")
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	if len(imgs) != 1 {
		t.Fatalf("got %d images, want 1", len(imgs))
	}
	if imgs[0].Counts.Critical != 1 {
		t.Errorf("critical = %d, want 1 (dual-scanner CVE must not double-count)", imgs[0].Counts.Critical)
	}
	if imgs[0].Counts.Total != 1 {
		t.Errorf("total = %d, want 1", imgs[0].Counts.Total)
	}

	fs, err := st.FleetStats(ctx, tenantID)
	if err != nil {
		t.Fatalf("FleetStats: %v", err)
	}
	if fs.Total != 1 || fs.Critical != 1 {
		t.Errorf("FleetStats total=%d critical=%d, want 1/1 (deduped)", fs.Total, fs.Critical)
	}
}

// TestFindingsBySBOM_DualScannerPaging is the keyset-tiebreak guard: when a CVE
// is found by both scanners (two rows, one finding_id) and results are paged so
// the twin pair straddles the boundary, BOTH rows must appear across the pages —
// a finding_id-only tiebreak would silently drop one.
func TestFindingsBySBOM_DualScannerPaging(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	var tenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"pg-"+hex.EncodeToString(b)+"@example.com").Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	sbomID := "pg-" + hex.EncodeToString(b)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_sbom (id, tenant_id, image_ref, digest, format, object_path)
		VALUES ($1,$2,'img','sha256:pg','cyclonedx','gs://x')`, sbomID, tenantID); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}
	// Three distinct CVEs, each found by BOTH scanners = 6 rows, all critical
	// (so they tie on the default severity sort and the tiebreak alone orders them).
	for i, cve := range []string{"CVE-A", "CVE-B", "CVE-C"} {
		fid := "fid-" + hex.EncodeToString([]byte{byte(i)})
		for _, sc := range []string{"grype", "trivy"} {
			if _, err := st.DB().ExecContext(ctx, `
				INSERT INTO devradar_finding (sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
				VALUES ($1,$2,$3,$4,'pkg','1.0','critical',9.8,false)`,
				sbomID, sc, fid, cve); err != nil {
				t.Fatalf("seed finding: %v", err)
			}
		}
	}

	// Page through 2 at a time; collect every (finding_id,scanner) seen.
	seen := map[string]int{}
	cursor := ""
	for range 10 {
		items, next, err := st.FindingsBySBOM(ctx, tenantID, sbomID, "low", false, false, "", "", cursor, 2)
		if err != nil {
			t.Fatalf("FindingsBySBOM: %v", err)
		}
		for _, f := range items {
			seen[f.Exposure+"|"+f.Scanner]++
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != 6 {
		t.Errorf("saw %d distinct (cve,scanner) rows across pages, want 6 (no twin dropped): %v", len(seen), seen)
	}
	for k, n := range seen {
		if n != 1 {
			t.Errorf("%s appeared %d times, want exactly 1", k, n)
		}
	}
}

// TestImageTimeline_AcrossDigests verifies the cross-digest history: two SBOMs
// sharing one image_ref (an image whose digest changed) produce a merged,
// severity-filtered, newest-first timeline; an unknown ref is 404; and the
// timeline is tenant-scoped.
func TestImageTimeline_AcrossDigests(t *testing.T) {
	st := testStore(t)
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
	st := testStore(t)
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
		f, _, err := st.FindingsBySBOM(ctx, tenantID, sbomID, "negligible", false, false, "", "", "", 50)
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
	all, _, _ := st.FindingsBySBOM(ctx, tenantID, sbomID, "negligible", false, true, "", "", "", 50)
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

// TestVEXSuppression_RepoScoped verifies a digest-less VEX statement (scoped to
// an image name) suppresses the CVE across every version of a matching
// repository, correlating on the repo's last path segment.
func TestVEXSuppression_RepoScoped(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	suffix := hex.EncodeToString(b)
	var tenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"vexr-"+suffix+"@example.com").Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	// Repository ghcr.io/nvidia/aicr-<suffix>; two versions (digests), same CVE.
	repo := "ghcr.io/nvidia/aicr-" + suffix
	cve := "CVE-2026-45447-" + suffix
	for _, v := range []string{"v1", "v2"} {
		sbomID := "aicr-" + v + "-" + suffix
		digest := "sha256:" + v + suffix
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_sbom (id, tenant_id, image_ref, repository, digest, format, object_path)
			VALUES ($1,$2,$3,$4,$5,'cyclonedx','gs://x')`, sbomID, tenantID, repo, repo, digest); err != nil {
			t.Fatalf("seed sbom %s: %v", v, err)
		}
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_finding (sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
			VALUES ($1,'grype',$2,$3,'p','1','high',7.0,false)`, sbomID, cve+"/p/1", cve); err != nil {
			t.Fatalf("seed finding %s: %v", v, err)
		}
	}

	// Repo-scoped VEX (no digest). The product key is the repo's last path segment
	// ("aicr-<suffix>"), which matches the tracked ghcr.io/nvidia/aicr-<suffix> —
	// the deliberate basename match that lets real vendor VEX docs apply drop-in.
	doc := &vex.Document{Author: "nvidia", Raw: []byte(`{}`), Statements: []vex.Statement{
		{ProductRepo: "aicr-" + suffix, Vulnerability: cve, Status: vex.StatusNotAffected,
			Justification: "vulnerable_code_not_in_execute_path"},
	}}
	if _, matched, err := st.SaveVEXDocument(ctx, tenantID, doc); err != nil || matched != 1 {
		t.Fatalf("save repo VEX: matched=%d err=%v", matched, err)
	}

	// Both versions' findings suppressed by the single repo-scoped statement.
	for _, v := range []string{"v1", "v2"} {
		f, _, err := st.FindingsBySBOM(ctx, tenantID, "aicr-"+v+"-"+suffix, "negligible", false, false, "", "", "", 50)
		if err != nil {
			t.Fatalf("findings %s: %v", v, err)
		}
		if len(f) != 0 {
			t.Errorf("%s: %d findings, want 0 (repo-scoped VEX should suppress)", v, len(f))
		}
	}
	// The fleet CVE view now SHOWS the repo-suppressed CVE, annotated as
	// not_affected (shown-but-dimmed), and a not_vexed filter excludes it.
	cves, _, err := st.FleetCVEs(ctx, tenantID, "negligible", postgres.FleetCVEFilter{}, "", "", "", 50)
	if err != nil {
		t.Fatalf("fleet cves: %v", err)
	}
	var got *postgres.FleetCVE
	for i := range cves {
		if cves[i].CVE == cve {
			got = &cves[i]
		}
	}
	if got == nil {
		t.Fatalf("repo-suppressed CVE %s should appear (annotated), not be dropped", cve)
	}
	if got.VEXStatus != "not_affected" || !got.Suppressed {
		t.Errorf("repo-suppressed CVE should be annotated not_affected/suppressed: %+v", got)
	}
	nv, _, _ := st.FleetCVEs(ctx, tenantID, "negligible", postgres.FleetCVEFilter{VEXState: "not_vexed"}, "", "", "", 50)
	for _, c := range nv {
		if c.CVE == cve {
			t.Errorf("not_vexed filter should exclude repo-suppressed CVE %s", cve)
		}
	}
}

// TestFleetCVEs_BlastRadiusRanking verifies CVEs are grouped across images,
// ranked KEV-first then severity then blast radius, and that CVEDetail lists
// every occurrence.
func TestFleetCVEs_BlastRadiusRanking(t *testing.T) {
	st := testStore(t)
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

	cves, _, err := st.FleetCVEs(ctx, tenantID, "negligible", postgres.FleetCVEFilter{}, "", "", "", 50)
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

func TestFleetCVEs_WorkQueueOrder(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	suffix := hex.EncodeToString(randomBytes(t, 8))
	var tenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"work-"+suffix+"@example.com").Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	sbomID := "work-" + suffix
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_sbom (id, tenant_id, image_ref, repository, digest, format, object_path)
		VALUES ($1,$2,'reg/work','reg/work',$3,'cyclonedx','gs://x')`,
		sbomID, tenantID, "sha256:"+suffix); err != nil {
		t.Fatal(err)
	}
	insert := func(scanner, findingID, cve, severity string, fixed bool, updated time.Time) {
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_finding
			(sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed, updated_at)
			VALUES ($1,$2,$3,$4,'pkg','1',$5,7,$6,$7)`,
			sbomID, scanner, findingID, cve, severity, fixed, updated); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 7, 11, 0, 0, 0, 0, time.UTC)
	fixable := "CVE-" + suffix + "-FIX"
	critical := "CVE-" + suffix + "-CRIT"
	insert("grype", "fix-id", fixable, "low", true, now)
	insert("trivy", "fix-id", fixable, "low", true, now)
	insert("grype", "crit-id", critical, "critical", false, now.Add(-24*time.Hour))

	items, _, err := st.FleetCVEs(ctx, tenantID, "negligible", postgres.FleetCVEFilter{}, "", "", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].CVE != fixable || items[1].CVE != critical {
		t.Fatalf("work order = %+v, want fixable before non-fixable critical", items)
	}
	if items[0].FindingCount != 1 || items[0].ScannerCount != 2 {
		t.Fatalf("scanner dedup/agreement = %+v", items[0])
	}
	if items[0].FirstSeen.IsZero() {
		t.Fatal("first seen must be populated")
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestFleetCVEs_VEXAnnotationAndFilters verifies VEX'd CVEs are INCLUDED in the
// fleet list (not dropped), annotated with status/justification/impact, and that
// the VEX/justification/KEV/fixable filters work.
func TestFleetCVEs_VEXAnnotationAndFilters(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	suffix := hex.EncodeToString(b)
	var tenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"vexcve-"+suffix+"@example.com").Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	repo := "reg/app-" + suffix
	digest := "sha256:" + suffix
	sbomID := "vc-" + suffix
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_sbom (id, tenant_id, image_ref, repository, digest, format, object_path)
		VALUES ($1,$2,$3,$3,$4,'cyclonedx','gs://x')`, sbomID, tenantID, repo, digest); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}
	openCVE, vexdCVE := "CVE-OPEN-"+suffix, "CVE-VEXD-"+suffix
	for _, cve := range []string{openCVE, vexdCVE} {
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_finding (sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
			VALUES ($1,'grype',$2,$3,'p','1','high',7.0,false)`, sbomID, cve+"/p/1", cve); err != nil {
			t.Fatalf("seed finding: %v", err)
		}
	}
	// VEX only the second CVE as not_affected, with a justification + impact.
	doc := &vex.Document{Author: "sec", Raw: []byte(`{}`), Statements: []vex.Statement{{
		ProductDigest: digest, Vulnerability: vexdCVE, Status: vex.StatusNotAffected,
		Justification: "vulnerable_code_not_in_execute_path", ImpactStatement: "not on the execution path",
	}}}
	if _, m, err := st.SaveVEXDocument(ctx, tenantID, doc); err != nil || m != 1 {
		t.Fatalf("save vex: matched=%d err=%v", m, err)
	}

	find := func(cves []postgres.FleetCVE, cve string) *postgres.FleetCVE {
		for i := range cves {
			if cves[i].CVE == cve {
				return &cves[i]
			}
		}
		return nil
	}

	// No filter: BOTH CVEs appear; the VEX'd one is annotated + Suppressed.
	all, _, err := st.FleetCVEs(ctx, tenantID, "negligible", postgres.FleetCVEFilter{}, "", "", "", 50)
	if err != nil {
		t.Fatalf("fleet cves: %v", err)
	}
	if find(all, openCVE) == nil || find(all, vexdCVE) == nil {
		t.Fatalf("both CVEs should appear (VEX'd shown, not dropped); got %d", len(all))
	}
	v := find(all, vexdCVE)
	if v.VEXStatus != "not_affected" || !v.Suppressed || v.Justification != "vulnerable_code_not_in_execute_path" || v.Impact == "" {
		t.Errorf("VEX'd CVE not annotated: %+v", v)
	}
	if o := find(all, openCVE); o.VEXStatus != "" {
		t.Errorf("open CVE should have no VEX status, got %q", o.VEXStatus)
	}

	// Filter not_vexed → only the open CVE.
	nv, _, _ := st.FleetCVEs(ctx, tenantID, "negligible", postgres.FleetCVEFilter{VEXState: "not_vexed"}, "", "", "", 50)
	if find(nv, openCVE) == nil || find(nv, vexdCVE) != nil {
		t.Errorf("not_vexed filter should show only the open CVE")
	}
	// Filter by justification → only the VEX'd CVE.
	jf, _, _ := st.FleetCVEs(ctx, tenantID, "negligible",
		postgres.FleetCVEFilter{Justification: "vulnerable_code_not_in_execute_path"}, "", "", "", 50)
	if find(jf, vexdCVE) == nil || find(jf, openCVE) != nil {
		t.Errorf("justification filter should show only the VEX'd CVE")
	}
	// The single-SBOM VEX'd CVE is fully covered.
	if !find(all, vexdCVE).AllVEXd {
		t.Errorf("single-image VEX'd CVE should be AllVEXd")
	}

	// PARTIAL case (the real-world AICR bug): a CVE on TWO images, VEX'd on only
	// one. It must still surface the VEX status but be marked partial (not fully
	// suppressed), and NOT dimmed as mitigated.
	partialCVE := "CVE-PART-" + suffix
	sbom2, digest2 := "vc2-"+suffix, "sha256:2"+suffix
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_sbom (id, tenant_id, image_ref, repository, digest, format, object_path)
		VALUES ($1,$2,'reg/other','reg/other',$3,'cyclonedx','gs://x')`, sbom2, tenantID, digest2); err != nil {
		t.Fatalf("seed sbom2: %v", err)
	}
	for _, sid := range []string{sbomID, sbom2} {
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_finding (sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
			VALUES ($1,'grype',$2,$3,'p','1','high',7.0,false)`, sid, partialCVE+"/p/1", partialCVE); err != nil {
			t.Fatalf("seed partial finding: %v", err)
		}
	}
	// VEX only the first image's occurrence (digest).
	pdoc := &vex.Document{Author: "sec", Raw: []byte(`{}`), Statements: []vex.Statement{{
		ProductDigest: digest, Vulnerability: partialCVE, Status: vex.StatusNotAffected,
		Justification: "component_not_present",
	}}}
	if _, _, err := st.SaveVEXDocument(ctx, tenantID, pdoc); err != nil {
		t.Fatalf("save partial vex: %v", err)
	}
	all2, _, _ := st.FleetCVEs(ctx, tenantID, "negligible", postgres.FleetCVEFilter{}, "", "", "", 50)
	p := find(all2, partialCVE)
	if p == nil {
		t.Fatalf("partial CVE should appear")
	}
	if p.VEXStatus != "not_affected" || !p.Suppressed {
		t.Errorf("partial CVE should surface not_affected status: %+v", p)
	}
	if p.AllVEXd {
		t.Errorf("partial CVE (VEX'd on 1 of 2 images) must NOT be AllVEXd")
	}
}

// TestFindings_PagingFilterRollup verifies findings page in worst-first order
// without gaps/overlaps, the fixable filter restricts the set, and the package
// rollup groups worst-severity-first.
func TestFindings_PagingFilterRollup(t *testing.T) {
	st := testStore(t)
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
		page, next, err := st.FindingsBySBOM(ctx, tenantID, sbomID, "negligible", false, false, "", "", cursor, 2)
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
	fx, _, err := st.FindingsBySBOM(ctx, tenantID, sbomID, "negligible", true, false, "", "", "", 50)
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

// TestFindings_Sorting verifies server-side sort by different columns/directions
// and that keyset pagination walks the sorted order without gaps or duplicates.
func TestFindings_Sorting(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	suffix := hex.EncodeToString(b)
	var tenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"sort-"+suffix+"@example.com").Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	sbomID := "sort-" + suffix
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_sbom (id, tenant_id, image_ref, repository, digest, format, object_path)
		VALUES ($1,$2,'reg/app','reg/app',$3,'cyclonedx','gs://x')`, sbomID, tenantID, "sha256:"+suffix); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}
	// Distinct scores + packages so ordering is unambiguous.
	seed := func(cve, pkg string, score float32) {
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO devradar_finding (sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
			VALUES ($1,'grype',$2,$3,$4,'1','medium',$5,false)`,
			sbomID, cve+"/"+pkg, cve, pkg, score); err != nil {
			t.Fatalf("seed finding: %v", err)
		}
	}
	seed("CVE-1"+suffix, "zeta", 2.0)
	seed("CVE-2"+suffix, "alpha", 9.0)
	seed("CVE-3"+suffix, "mike", 5.0)

	scores := func(sortKey, dir string) []float32 {
		f, _, err := st.FindingsBySBOM(ctx, tenantID, sbomID, "negligible", false, false, sortKey, dir, "", 50)
		if err != nil {
			t.Fatalf("findings sort %s/%s: %v", sortKey, dir, err)
		}
		out := make([]float32, len(f))
		for i, x := range f {
			out[i] = x.Score
		}
		return out
	}

	// CVSS desc: 9,5,2. asc: 2,5,9.
	if got := scores("cvss", "desc"); len(got) != 3 || got[0] != 9.0 || got[2] != 2.0 {
		t.Errorf("cvss desc = %v, want [9 5 2]", got)
	}
	if got := scores("cvss", "asc"); len(got) != 3 || got[0] != 2.0 || got[2] != 9.0 {
		t.Errorf("cvss asc = %v, want [2 5 9]", got)
	}

	// Package asc: alpha(9), mike(5), zeta(2) → scores 9,5,2.
	if got := scores("package", "asc"); len(got) != 3 || got[0] != 9.0 || got[2] != 2.0 {
		t.Errorf("package asc scores = %v, want [9 5 2]", got)
	}

	// Paging under cvss desc: page size 2 then 1, no gap/overlap.
	p1, next, err := st.FindingsBySBOM(ctx, tenantID, sbomID, "negligible", false, false, "cvss", "desc", "", 2)
	if err != nil || len(p1) != 2 || next == "" {
		t.Fatalf("cvss page1: len=%d next=%q err=%v", len(p1), next, err)
	}
	p2, _, err := st.FindingsBySBOM(ctx, tenantID, sbomID, "negligible", false, false, "cvss", "desc", next, 2)
	if err != nil || len(p2) != 1 {
		t.Fatalf("cvss page2: len=%d err=%v", len(p2), err)
	}
	all := []float32{p1[0].Score, p1[1].Score, p2[0].Score}
	if all[0] != 9.0 || all[1] != 5.0 || all[2] != 2.0 {
		t.Errorf("paged cvss desc = %v, want [9 5 2]", all)
	}
}

// TestListRepoImages_RiskOrderAndPaging verifies images come back risk-ranked
// (critical, then high, then total) from SQL, that keyset pagination walks that
// order without gaps or overlaps, and that FleetStats is a whole-tenant rollup
// independent of the page.
func TestListRepoImages_RiskOrderAndPaging(t *testing.T) {
	st := testStore(t)
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
		// Findings are seeded directly here (no ApplyScan), so build the rollup the
		// read path sums from.
		if err := st.RecomputeSBOMRollup(ctx, digest); err != nil {
			t.Fatalf("recompute rollup %s: %v", name, err)
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
	all, _, err := st.ListRepoImages(ctx, tenantID, "negligible", "", "", "", "", "", 50)
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
	p1, next, err := st.ListRepoImages(ctx, tenantID, "negligible", "", "", "", "", "", 2)
	if err != nil || len(p1) != 2 || next == "" {
		t.Fatalf("page1: len=%d next=%q err=%v", len(p1), next, err)
	}
	p2, next2, err := st.ListRepoImages(ctx, tenantID, "negligible", "", "", "", "", next, 2)
	if err != nil || len(p2) != 1 || next2 != "" {
		t.Fatalf("page2: len=%d next=%q err=%v", len(p2), next2, err)
	}
	if p1[0].Repository != wantOrder[0] || p1[1].Repository != wantOrder[1] || p2[0].Repository != wantOrder[2] {
		t.Errorf("paged order wrong: %s,%s then %s", p1[0].Repository, p1[1].Repository, p2[0].Repository)
	}

	// Sort by repository ascending overrides the risk default.
	byRepo, _, err := st.ListRepoImages(ctx, tenantID, "negligible", "", "", "repository", "asc", "", 50)
	if err != nil {
		t.Fatalf("sort by repository: %v", err)
	}
	if byRepo[0].Repository != "reg/a-"+suffix || byRepo[2].Repository != "reg/c-"+suffix {
		t.Errorf("repository asc = %v, want a,b,c", []string{byRepo[0].Repository, byRepo[1].Repository, byRepo[2].Repository})
	}
	// Sort by total desc: C(3) → B(2) → A(1).
	byTotal, _, err := st.ListRepoImages(ctx, tenantID, "negligible", "", "", "total", "desc", "", 50)
	if err != nil {
		t.Fatalf("sort by total: %v", err)
	}
	if byTotal[0].Repository != "reg/c-"+suffix || byTotal[2].Repository != "reg/a-"+suffix {
		t.Errorf("total desc = %v, want c,b,a", []string{byTotal[0].Repository, byTotal[1].Repository, byTotal[2].Repository})
	}
}

// TestSBOMLabels verifies grouping labels are stored at upsert (union on
// re-submit), listed per tenant, and filter the image list.
func TestSBOMLabels(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	suffix := hex.EncodeToString(b)
	var tenantID string
	if err := st.DB().QueryRowContext(ctx,
		`INSERT INTO devradar_tenant (email) VALUES ($1) RETURNING id`,
		"label-"+suffix+"@example.com").Scan(&tenantID); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	// Two images: prodImg labeled "prod", edgeImg labeled "edge".
	mk := func(repo string, labels []string) {
		if _, _, _, err := st.UpsertSBOM(ctx, &postgres.SBOM{
			ID: repo + suffix, TenantID: tenantID, ImageRef: repo, Repository: repo,
			Digest: "sha256:" + repo + suffix, Format: "cyclonedx", ObjectPath: "gs://x", Labels: labels, Status: "active",
		}); err != nil {
			t.Fatalf("upsert %s: %v", repo, err)
		}
	}
	mk("reg/prod-"+suffix, []string{"prod"})
	mk("reg/edge-"+suffix, []string{"edge"})

	// Re-submit prod image with an extra label → union, no dup.
	mk("reg/prod-"+suffix, []string{"prod", "team-x"})

	labels, err := st.TenantLabels(ctx, tenantID)
	if err != nil {
		t.Fatalf("tenant labels: %v", err)
	}
	// Expect edge, prod, team-x (sorted, deduped).
	want := map[string]bool{"edge": true, "prod": true, "team-x": true}
	if len(labels) != 3 {
		t.Fatalf("tenant labels = %v, want 3 distinct", labels)
	}
	for _, l := range labels {
		if !want[l] {
			t.Errorf("unexpected label %q", l)
		}
	}

	// Filter by "edge" → only the edge image.
	edge, _, err := st.ListRepoImages(ctx, tenantID, "negligible", "", "edge", "", "", "", 50)
	if err != nil {
		t.Fatalf("filter edge: %v", err)
	}
	if len(edge) != 1 || edge[0].Repository != "reg/edge-"+suffix {
		t.Errorf("label=edge filter = %v, want just the edge image", edge)
	}
	// Filter by "team-x" (added on re-submit) → only the prod image.
	tx, _, _ := st.ListRepoImages(ctx, tenantID, "negligible", "", "team-x", "", "", "", 50)
	if len(tx) != 1 || tx[0].Repository != "reg/prod-"+suffix {
		t.Errorf("label=team-x filter = %v, want just the prod image", tx)
	}
	// No filter → both images.
	all, _, _ := st.ListRepoImages(ctx, tenantID, "negligible", "", "", "", "", "", 50)
	if len(all) != 2 {
		t.Errorf("no label filter = %d images, want 2", len(all))
	}
}

// TestRepoViews covers the CUJ endpoints: grouping SBOMs by repository, listing
// an image's SBOMs newest-generation-first, the cross-digest repo timeline, and
// keyset pagination on each.
func TestRepoViews(t *testing.T) {
	st := testStore(t)
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
	imgs, _, err := st.ListRepoImages(ctx, tenantID, "negligible", "", "", "", "", "", 50)
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
	sboms, _, err := st.SBOMsForRepo(ctx, tenantID, repo, "", "", "", 50)
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
	if _, _, err := st.SBOMsForRepo(ctx, tenantID, "quay.io/nope", "", "", "", 50); !errors.Is(err, postgres.ErrNotFound) {
		t.Errorf("unknown repo: err = %v, want ErrNotFound", err)
	}

	// Keyset pagination on the repo timeline: page size 2 → 2 rows + a cursor,
	// then the remaining 1 with no further cursor. No overlap, no gap.
	p1, next, err := st.RepoTimeline(ctx, tenantID, repo, "negligible", true, "", "", "", 2)
	if err != nil {
		t.Fatalf("RepoTimeline p1: %v", err)
	}
	if len(p1) != 2 || next == "" {
		t.Fatalf("page1: len=%d next=%q, want 2 + cursor", len(p1), next)
	}
	p2, next2, err := st.RepoTimeline(ctx, tenantID, repo, "negligible", true, "", "", next, 2)
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

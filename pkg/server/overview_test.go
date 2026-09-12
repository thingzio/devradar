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

package server_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/data/postgres"
)

func TestOverviewSignals(t *testing.T) {
	srv, st := testServer(t)
	ctx := context.Background()
	tenantID, _ := seedTenantToken(t, st)
	foreignTenantID, _ := seedTenantToken(t, st)
	sb := seedLabeledSBOM(t, st, tenantID, "overview-signals")
	foreignSB := seedLabeledSBOM(t, st, foreignTenantID, "foreign-sentinel")
	seedAlertSBOMGeneration(t, st, sb, tenantID, "v2", time.Now().UTC())
	seedAlertSBOMGeneration(t, st, foreignSB, foreignTenantID, "v2", time.Now().UTC())

	seedOverviewFinding(t, st, sb, "grype", "overview-kev", "CVE-2026-7101", "medium", false)
	seedOverviewFinding(t, st, sb, "trivy", "overview-kev", "CVE-2026-7101", "medium", false)
	seedOverviewFinding(t, st, sb, "grype", "overview-fixable", "CVE-2026-7102", "high", true)
	seedOverviewFinding(t, st, sb, "grype", "overview-critical", "CVE-2026-7103", "critical", false)
	seedOverviewFinding(t, st, sb, "grype", "overview-fourth", "CVE-2026-7104", "medium", false)
	seedOverviewFinding(t, st, foreignSB, "grype", "foreign-finding", "foreign-sentinel", "critical", true)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_cve_enrichment (cve, kev, epss_score)
		VALUES
			('CVE-2026-7101', true, 0.91),
			('CVE-2026-7102', false, 0.72),
			('CVE-2026-7103', false, 0.63)
		ON CONFLICT (cve) DO UPDATE SET kev=EXCLUDED.kev, epss_score=EXCLUDED.epss_score`); err != nil {
		t.Fatalf("seed overview enrichment: %v", err)
	}

	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_tenant_posture_snapshot
			(tenant_id, snapshot_date, images, relevant_findings, critical, high, medium, low, fixable, kev)
		VALUES
			($1, CURRENT_DATE - 1, 1, 8, 1, 2, 3, 2, 3, 1),
			($1, CURRENT_DATE, 1, 11, 2, 3, 4, 2, 4, 1),
			($2, CURRENT_DATE, 99, 9999, 99, 99, 99, 99, 99, 99)`, tenantID, foreignTenantID); err != nil {
		t.Fatalf("seed overview posture: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_license_policy (tenant_id, denied_categories)
		VALUES ($1, ARRAY['strong-copyleft']), ($2, ARRAY['proprietary'])`, tenantID, foreignTenantID); err != nil {
		t.Fatalf("seed overview license policies: %v", err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_sbom_package (sbom_id, package, version, licenses)
		VALUES
			($1, 'copyleft-package', '1', ARRAY['GPL-3.0']),
			($2, 'foreign-sentinel', '1', ARRAY['LicenseRef-Proprietary'])`, sb.ID, foreignSB.ID); err != nil {
		t.Fatalf("seed overview licenses: %v", err)
	}

	body := getOverview(t, srv, st, tenantID)
	for _, want := range []string{
		"Current posture", "What needs attention", "Full work queue",
		"Direction of travel", "Day-over-day change", "View trends",
		"3 more findings",
		"License policy", "1 policy violation", "View licenses",
		"Compare releases", "1 repository ready", "Choose digests",
		"CVE-2026-7101", "CVE-2026-7102", "CVE-2026-7103",
		"KEV", "Fix available", "Reported by 2 scanners",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q", want)
		}
	}
	if got := strings.Count(body, `class="overview-work-item`); got != 3 {
		t.Fatalf("work preview count = %d, want 3", got)
	}
	first, second, third := strings.Index(body, "CVE-2026-7101"), strings.Index(body, "CVE-2026-7102"), strings.Index(body, "CVE-2026-7103")
	if first < 0 || second < first || third < second {
		t.Fatalf("work preview is not in risk order: indexes %d, %d, %d", first, second, third)
	}
	for _, want := range []string{`href="/work"`, `href="/trends"`, `href="/licenses"`, `href="/dashboard"`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing canonical link %q", want)
		}
	}
	for _, forbidden := range []string{"CVE-2026-7104", "foreign-sentinel", "safe", "compatible", "reachable", "compliant"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(forbidden)) {
			t.Fatalf("forbidden/leaked %q", forbidden)
		}
	}
}

func TestOverviewSignalEmptyStates(t *testing.T) {
	srv, st := testServer(t)
	ctx := context.Background()
	var gapDate string
	if err := st.DB().QueryRowContext(ctx, `SELECT to_char(CURRENT_DATE - 4, 'YYYY-MM-DD')`).Scan(&gapDate); err != nil {
		t.Fatalf("read gap date: %v", err)
	}

	tests := []struct {
		name      string
		setup     func(*testing.T, string, *postgres.SBOM)
		want      []string
		forbidden []string
	}{
		{
			name: "no snapshots",
			want: []string{"Coverage begins with the first snapshot"},
		},
		{
			name: "one point",
			setup: func(t *testing.T, tenantID string, _ *postgres.SBOM) {
				seedOverviewSnapshot(t, st, tenantID, "CURRENT_DATE", 5)
			},
			want: []string{"No prior snapshot"},
		},
		{
			name: "date gap",
			setup: func(t *testing.T, tenantID string, _ *postgres.SBOM) {
				seedOverviewSnapshot(t, st, tenantID, "CURRENT_DATE - 4", 7)
				seedOverviewSnapshot(t, st, tenantID, "CURRENT_DATE", 4)
			},
			want: []string{"Change since " + gapDate, "3 fewer findings"},
		},
		{
			name: "empty policy",
			want: []string{"No policy configured", `href="/tokens"`, "Settings →"},
		},
		{
			name: "configured zero violations",
			setup: func(t *testing.T, tenantID string, sb *postgres.SBOM) {
				if _, err := st.DB().ExecContext(ctx, `
					INSERT INTO devradar_license_policy (tenant_id, denied_categories)
					VALUES ($1, ARRAY['strong-copyleft'])`, tenantID); err != nil {
					t.Fatalf("seed zero-violation policy: %v", err)
				}
				if _, err := st.DB().ExecContext(ctx, `
					INSERT INTO devradar_sbom_package (sbom_id, package, version, licenses)
					VALUES ($1, 'permissive-package', '1', ARRAY['MIT'])`, sb.ID); err != nil {
					t.Fatalf("seed zero-violation package: %v", err)
				}
			},
			want:      []string{"0 policy violations"},
			forbidden: []string{"No policy configured"},
		},
		{
			name: "zero comparison ready repositories",
			want: []string{"No repositories ready", "Submit another digest"},
		},
	}

	t.Run("no tracked images", func(t *testing.T) {
		tenantID, _ := seedTenantToken(t, st)
		body := getOverview(t, srv, st, tenantID)
		for _, want := range []string{"Welcome to DevRadar", "Submit your first SBOM"} {
			if !strings.Contains(body, want) {
				t.Errorf("missing %q body=%s", want, body)
			}
		}
		if strings.Contains(body, "Current posture") {
			t.Fatalf("empty tenant rendered current posture: %s", body)
		}
	})

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tenantID, _ := seedTenantToken(t, st)
			sb := seedLabeledSBOM(t, st, tenantID, "overview-empty-"+strings.ReplaceAll(tc.name, " ", "-"))
			if tc.setup != nil {
				tc.setup(t, tenantID, sb)
			}
			body := getOverview(t, srv, st, tenantID)
			for _, want := range tc.want {
				if !strings.Contains(body, want) {
					t.Errorf("missing %q body=%s", want, body)
				}
			}
			for _, forbidden := range tc.forbidden {
				if strings.Contains(body, forbidden) {
					t.Errorf("unexpected %q body=%s", forbidden, body)
				}
			}
		})
	}
}

func TestOverviewTrackedImageWithNoFindings(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	seedLabeledSBOM(t, st, tenantID, "overview-zero-findings")
	body := getOverview(t, srv, st, tenantID)
	if !strings.Contains(body, "Current posture") || !strings.Contains(body, "What needs attention") {
		t.Fatalf("tracked zero-finding image did not render posture: %s", body)
	}
	if strings.Contains(body, "Welcome to DevRadar") || strings.Contains(body, "Submit your first SBOM") {
		t.Fatalf("tracked zero-finding image rendered first-SBOM onboarding: %s", body)
	}
}

func getOverview(t *testing.T, srv interface{ Handler() http.Handler }, st *postgres.Store, tenantID string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/overview", nil)
	req.AddCookie(seedSession(t, st, tenantID))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /overview = %d body=%s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func seedOverviewFinding(t *testing.T, st *postgres.Store, sb *postgres.SBOM, scanner, findingID, cve, severity string, fixed bool) {
	t.Helper()
	if _, err := st.DB().ExecContext(context.Background(), `
		INSERT INTO devradar_finding
			(sbom_id, scanner, finding_id, exposure, package, version, severity, score, is_fixed)
		VALUES ($1,$2,$3,$4,'overview-package','1',$5,8.1,$6)`,
		sb.ID, scanner, findingID, cve, severity, fixed); err != nil {
		t.Fatalf("seed overview finding: %v", err)
	}
}

func seedOverviewSnapshot(t *testing.T, st *postgres.Store, tenantID, dateExpr string, total int) {
	t.Helper()
	query := fmt.Sprintf(`
		INSERT INTO devradar_tenant_posture_snapshot
			(tenant_id, snapshot_date, images, relevant_findings)
		VALUES ($1, %s, 1, $2)`, dateExpr)
	if _, err := st.DB().ExecContext(context.Background(), query, tenantID, total); err != nil {
		t.Fatalf("seed overview snapshot: %v", err)
	}
}

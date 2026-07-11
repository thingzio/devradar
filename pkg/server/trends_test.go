package server_test

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTrendsPage_RequiresAuthAndIsolatesTenant(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	otherTenantID, _ := seedTenantToken(t, st)
	ctx := context.Background()
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_tenant_posture_snapshot
			(tenant_id, snapshot_date, images, relevant_findings, critical, high, medium, low, fixable, kev)
		VALUES
			($1, CURRENT_DATE - 100, 1, 30, 8, 10, 7, 5, 12, 4),
			($1, CURRENT_DATE - 2, 2, 20, 6, 7, 4, 3, 10, 3),
			($1, CURRENT_DATE - 1, 2, 11, 4, 5, 1, 1, 7, 2),
			($1, CURRENT_DATE, 3, 14, 3, 6, 3, 2, 8, 2),
			($2, CURRENT_DATE, 99, 9876, 99, 99, 99, 99, 99, 99)`, tenantID, otherTenantID); err != nil {
		t.Fatal(err)
	}
	var coverageStart, firstDate, currentDate string
	if err := st.DB().QueryRowContext(ctx, `
		SELECT to_char(CURRENT_DATE - 100, 'YYYY-MM-DD'),
		       to_char(CURRENT_DATE - 2, 'YYYY-MM-DD'),
		       to_char(CURRENT_DATE, 'YYYY-MM-DD')`).
		Scan(&coverageStart, &firstDate, &currentDate); err != nil {
		t.Fatal(err)
	}

	h := srv.Handler()
	req := httptest.NewRequest(http.MethodGet, "/trends?days=30", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("unauthenticated trends = %d, want 302", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/trends?days=30", nil)
	req.AddCookie(seedSession(t, st, tenantID))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body := html.UnescapeString(rec.Body.String())
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /trends = %d body=%s", rec.Code, body)
	}
	for _, want := range []string{
		"Fleet posture trends",
		`aria-current="page"`,
		`<span class="stat-n trend-value">14</span>`,
		`<span class="trend-delta trend-up">+3</span>`,
		`<span class="trend-delta trend-down">-1</span>`,
		`Coverage began <time datetime="` + coverageStart + `">` + coverageStart + `</time>`,
		`First snapshot in selected window <time datetime="` + firstDate + `">` + firstDate + `</time>`,
		`Last snapshot in selected window <time datetime="` + currentDate + `">` + currentDate + `</time>`,
		`data-snapshot-date="` + currentDate + `"`,
		currentDate + ": 14 findings",
		`<span class="stat-n trend-value danger-n">3</span>`,
		`<span class="stat-n trend-value kev-n">2</span>`,
		`<h2 id="posture-history-title">Snapshot history</h2>`,
		`<div class="trend-table-wrap" tabindex="0" role="region" aria-labelledby="posture-history-title">`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("GET /trends missing %q body=%s", want, body)
		}
	}
	if strings.Contains(body, "9876") {
		t.Fatalf("GET /trends exposed another tenant's snapshot: %s", body)
	}
	normalized := strings.Join(strings.Fields(body), " ")
	if !strings.Contains(normalized, `<span class="stat-n trend-value">8</span> <span class="stat-l">Fixable</span> <span class="trend-delta trend-neutral">+1</span>`) {
		t.Fatalf("fixable delta must remain directionally neutral: %s", body)
	}
}

func TestTrendsPage_DistinguishesOutOfWindowFromNoLifetimeSnapshots(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	emptyTenantID, _ := seedTenantToken(t, st)
	ctx := context.Background()
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_tenant_posture_snapshot
			(tenant_id, snapshot_date, images, relevant_findings)
		VALUES ($1, CURRENT_DATE - 100, 1, 7)`, tenantID); err != nil {
		t.Fatal(err)
	}
	var coverageStart string
	if err := st.DB().QueryRowContext(ctx, `SELECT to_char(CURRENT_DATE - 100, 'YYYY-MM-DD')`).Scan(&coverageStart); err != nil {
		t.Fatal(err)
	}

	h := srv.Handler()
	req := httptest.NewRequest(http.MethodGet, "/trends?days=30", nil)
	req.AddCookie(seedSession(t, st, tenantID))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "No snapshots in this 30-day window") ||
		!strings.Contains(body, `Coverage began <time datetime="`+coverageStart+`">`+coverageStart+`</time>`) ||
		strings.Contains(body, "No posture snapshots yet") {
		t.Fatalf("out-of-window trends = %d body=%s", rec.Code, body)
	}

	req = httptest.NewRequest(http.MethodGet, "/trends?days=30", nil)
	req.AddCookie(seedSession(t, st, emptyTenantID))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body = rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "No posture snapshots yet") ||
		strings.Contains(body, "No snapshots in this 30-day window") || strings.Contains(body, "Coverage began") {
		t.Fatalf("no-lifetime trends = %d body=%s", rec.Code, body)
	}
}

func TestTrendsPage_StartsAtFirstRealSnapshot(t *testing.T) {
	srv, st := testServer(t)
	tenantID, _ := seedTenantToken(t, st)
	ctx := context.Background()
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO devradar_tenant_posture_snapshot
			(tenant_id, snapshot_date, images, relevant_findings, critical, high, fixable, kev)
		VALUES ($1, CURRENT_DATE, 1, 5, 1, 2, 3, 0)`, tenantID); err != nil {
		t.Fatal(err)
	}
	var priorDate string
	if err := st.DB().QueryRowContext(ctx, `SELECT to_char(CURRENT_DATE - 1, 'YYYY-MM-DD')`).Scan(&priorDate); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/trends", nil)
	req.AddCookie(seedSession(t, st, tenantID))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || strings.Count(body, `class="trend-row"`) != 1 {
		t.Fatalf("single-snapshot trends = %d body=%s", rec.Code, body)
	}
	if !strings.Contains(body, "No prior snapshot is available for comparison.") ||
		strings.Contains(body, `data-snapshot-date="`+priorDate+`"`) {
		t.Fatalf("trend synthesized history or hid coverage: %s", body)
	}
}

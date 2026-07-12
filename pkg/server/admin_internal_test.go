package server

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thingzio/devradar/pkg/data/postgres"
)

type failingAdminProductHealthReader struct{}

var errProductHealthUnavailable = errors.New("product health unavailable")

func (failingAdminProductHealthReader) AdminProductHealth(context.Context) (*postgres.AdminProductHealth, error) {
	return nil, errProductHealthUnavailable
}

func TestLoadAdminProductHealth_PreservesCoreDashboardOnFailure(t *testing.T) {
	counts := &postgres.PlatformCounts{
		Tenants: 7, SBOMsActive: 11,
		FindingsBySev:    map[string]int{},
		EventsByCause24h: map[string]int{},
	}
	rows := []trendRow{{Label: "Core trend preserved", Cells: []trendCell{{Has: true, Delta: 4}}}}

	health, err := loadAdminProductHealth(context.Background(), failingAdminProductHealthReader{})
	if health != nil {
		t.Fatalf("health = %+v, want nil", health)
	}
	if !errors.Is(err, errProductHealthUnavailable) {
		t.Fatalf("error = %v, want %v", err, errProductHealthUnavailable)
	}

	data := adminDashboardData(counts, rows, health, err, time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC))
	data["SignedIn"] = true
	data["AdminTab"] = "dashboard"
	data["Version"] = "test"
	if data["Counts"] != counts || counts.Tenants != 7 || counts.SBOMsActive != 11 {
		t.Fatalf("core dashboard counts changed: %+v", data["Counts"])
	}
	if got := data["TrendRows"].([]trendRow); len(got) != 1 || got[0].Label != "Core trend preserved" {
		t.Fatalf("core dashboard trends changed: %+v", got)
	}
	var body bytes.Buffer
	if err := templates.ExecuteTemplate(&body, "admin_dashboard.html", data); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`<span class="stat-n">7</span>`, "Core trend preserved", "&#43;4", "Product health temporarily unavailable."} {
		if !strings.Contains(body.String(), want) {
			t.Errorf("degraded dashboard missing %q", want)
		}
	}
}

func TestAdminDashboardProductHealth_CaughtUpWithoutDatabaseMutation(t *testing.T) {
	data := map[string]any{
		"Title":    "Admin — Dashboard",
		"SignedIn": true,
		"AdminTab": "dashboard",
		"Version":  "test",
		"Counts": &postgres.PlatformCounts{
			FindingsBySev:    map[string]int{},
			EventsByCause24h: map[string]int{},
		},
		"ProductHealth":        &postgres.AdminProductHealth{},
		"ProductHealthUTCDate": "2026-07-11",
	}
	var body bytes.Buffer
	if err := templates.ExecuteTemplate(&body, "admin_dashboard.html", data); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Product health", "Caught up", "No active tenants", "current UTC date 2026-07-11"} {
		if !strings.Contains(body.String(), want) {
			t.Errorf("rendered dashboard missing %q", want)
		}
	}
	for _, heading := range []string{
		"Alert adoption", "Evaluator", "Posture coverage", "Actionable exposure",
		"Comparison readiness", "License policy adoption",
	} {
		want := `<h2 role="heading" aria-level="3">` + heading + `</h2>`
		if !strings.Contains(body.String(), want) {
			t.Errorf("product-health subgroup missing level-3 heading %q", heading)
		}
	}
}

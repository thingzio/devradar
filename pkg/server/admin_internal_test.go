package server

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/thingzio/devradar/pkg/data/postgres"
)

type failingAdminProductHealthReader struct{}

var errProductHealthUnavailable = errors.New("product health unavailable")

func (failingAdminProductHealthReader) AdminProductHealth(context.Context) (*postgres.AdminProductHealth, error) {
	return nil, errProductHealthUnavailable
}

func TestLoadAdminProductHealth_PreservesCoreDashboardOnFailure(t *testing.T) {
	counts := &postgres.PlatformCounts{Tenants: 7, SBOMsActive: 11}
	coreDashboard := map[string]any{
		"Counts":    counts,
		"TrendRows": []trendRow{{Label: "Tenants"}},
	}

	health, err := loadAdminProductHealth(context.Background(), failingAdminProductHealthReader{})

	if health != nil {
		t.Fatalf("health = %+v, want nil", health)
	}
	if !errors.Is(err, errProductHealthUnavailable) {
		t.Fatalf("error = %v, want %v", err, errProductHealthUnavailable)
	}
	if coreDashboard["Counts"] != counts || counts.Tenants != 7 || counts.SBOMsActive != 11 {
		t.Fatalf("core dashboard counts changed: %+v", coreDashboard["Counts"])
	}
	if got := coreDashboard["TrendRows"].([]trendRow); len(got) != 1 || got[0].Label != "Tenants" {
		t.Fatalf("core dashboard trends changed: %+v", got)
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
}

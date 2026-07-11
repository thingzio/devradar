package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
)

type workRow struct {
	CVE          string
	Severity     string
	KEV          bool
	Fixable      bool
	EPSS         string
	ImageCount   int
	FindingCount int
	Age          string
	Agreement    string
	Repositories []string
	AllVEXd      bool
}

type workView struct {
	Title      string
	SignedIn   bool
	Tab        string
	Email      string
	AvatarURL  string
	Version    string
	Items      []workRow
	NextCursor string
}

func (s *Server) handleWorkQueue(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	items, next, err := s.store.FleetCVEs(r.Context(), tn.ID, tenantMinSeverity(tn),
		postgres.FleetCVEFilter{}, "risk", "desc", r.URL.Query().Get("cursor"), 100)
	if err != nil {
		http.Error(w, "failed to load work queue", http.StatusInternalServerError)
		return
	}
	v := workView{
		Title: "What should I fix?", SignedIn: true, Tab: "work", Email: tn.Email,
		AvatarURL: tn.AvatarURL, Version: s.opts.Version, NextCursor: next,
	}
	for _, item := range items {
		agreement := "Single-scanner signal"
		if item.ScannerCount > 1 {
			agreement = fmt.Sprintf("%d scanners agree", item.ScannerCount)
		}
		age := "first seen just now"
		if !item.FirstSeen.IsZero() {
			age = "first seen " + humanizeSince(time.Since(item.FirstSeen))
		}
		v.Items = append(v.Items, workRow{
			CVE: item.CVE, Severity: item.WorstSev, KEV: item.KEV, Fixable: item.Fixable,
			EPSS: formatEPSS(item.EPSS), ImageCount: item.ImageCount, FindingCount: item.FindingCount,
			Age: age, Agreement: agreement, Repositories: item.Repositories, AllVEXd: item.AllVEXd,
		})
	}
	render(w, "work.html", v)
}

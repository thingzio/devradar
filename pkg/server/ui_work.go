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
	Suppressed   bool
	AllVEXd      bool
}

type workView struct {
	chromeView
	Items      []workRow
	NextCursor string
}

func (s *Server) handleWorkQueue(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	items, next, err := s.store.FleetCVEs(r.Context(), access.Account.ID, accountMinSeverity(&access.Account),
		postgres.FleetCVEFilter{}, "risk", "desc", r.URL.Query().Get("cursor"), 100)
	if err != nil {
		http.Error(w, "failed to load work queue", http.StatusInternalServerError)
		return
	}
	v := workView{
		chromeView: s.chrome(access, "What should I fix?", "work"), NextCursor: next, Items: workRows(items),
	}
	render(w, "work.html", v)
}

func workRows(items []postgres.FleetCVE) []workRow {
	rows := make([]workRow, 0, len(items))
	for _, item := range items {
		agreement := "Single-scanner signal"
		if item.ScannerCount > 1 {
			agreement = fmt.Sprintf("Reported by %d scanners", item.ScannerCount)
		}
		age := "first seen just now"
		if !item.FirstSeen.IsZero() {
			age = "first seen " + humanizeSince(time.Since(item.FirstSeen))
		}
		rows = append(rows, workRow{
			CVE: item.CVE, Severity: item.WorstSev, KEV: item.KEV, Fixable: item.Fixable,
			EPSS: formatEPSS(item.EPSS), ImageCount: item.ImageCount, FindingCount: item.FindingCount,
			Age: age, Agreement: agreement, Repositories: item.Repositories,
			Suppressed: item.Suppressed, AllVEXd: item.AllVEXd,
		})
	}
	return rows
}

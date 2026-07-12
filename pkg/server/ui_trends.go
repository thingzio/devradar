package server

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
)

const defaultTrendDays = 30

type trendDayOption struct {
	Value    int
	Selected bool
}

type trendRepositoryOption struct {
	Repository    string
	CoverageStart string
	Selected      bool
}

type trendStat struct {
	Label        string
	Value        int
	Tone         string
	DeltaText    string
	DeltaClass   string
	NeutralDelta bool
}

type fleetTrendRow struct {
	Date string
	postgres.TenantPosturePoint
}

type trendsView struct {
	Title, Tab, Email, AvatarURL, Version string
	SignedIn                              bool
	Days                                  int
	DayOptions                            []trendDayOption
	SelectedRepository                    string
	RepositoryOptions                     []trendRepositoryOption
	HasData, HasPrevious, HasLifetimeData bool
	CoverageStart                         string
	WindowFirstDate, WindowLastDate       string
	SnapshotCount                         int
	ComparisonLabel                       string
	Stats                                 []trendStat
	Rows                                  []fleetTrendRow
	Chart                                 template.HTML
}

func (s *Server) handleTrends(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	days := trendDays(r.URL.Query().Get("days"))
	repository := r.URL.Query().Get("repository")
	repositories, err := s.store.RepositoryPostureOptions(r.Context(), tn.ID)
	if err != nil {
		http.Error(w, "failed to load posture trends", http.StatusInternalServerError)
		return
	}
	repositoryOptions := make([]trendRepositoryOption, 0, len(repositories))
	var selectedCoverage *time.Time
	for _, option := range repositories {
		selected := option.Repository == repository
		repositoryOptions = append(repositoryOptions, trendRepositoryOption{
			Repository: option.Repository, CoverageStart: option.CoverageStart.Format(time.DateOnly), Selected: selected,
		})
		if selected {
			coverage := option.CoverageStart
			selectedCoverage = &coverage
		}
	}

	var points []postgres.TenantPosturePoint
	var coverageStart *time.Time
	if repository == "" {
		points, err = s.store.TenantPostureTrend(r.Context(), tn.ID, days)
		if err == nil {
			coverageStart, err = s.store.TenantPostureCoverageStart(r.Context(), tn.ID)
		}
	} else {
		if selectedCoverage == nil {
			http.NotFound(w, r)
			return
		}
		points, err = s.store.RepositoryPostureTrend(r.Context(), tn.ID, repository, days)
		coverageStart = selectedCoverage
	}
	if err != nil {
		http.Error(w, "failed to load posture trends", http.StatusInternalServerError)
		return
	}

	v := trendsView{
		Title: "Fleet posture trends", SignedIn: true, Tab: "trends", Email: tn.Email,
		AvatarURL: tn.AvatarURL, Version: s.opts.Version, Days: days,
		DayOptions: trendDayOptions(days), SnapshotCount: len(points), SelectedRepository: repository,
		RepositoryOptions: repositoryOptions,
	}
	if repository != "" {
		v.Title = "Repository posture trends"
	}
	if coverageStart != nil {
		v.HasLifetimeData = true
		v.CoverageStart = coverageStart.Format(time.DateOnly)
	}
	if len(points) == 0 {
		render(w, "trends.html", v)
		return
	}

	v.HasData = true
	v.WindowFirstDate = points[0].Date.Format(time.DateOnly)
	v.WindowLastDate = points[len(points)-1].Date.Format(time.DateOnly)
	v.Rows = make([]fleetTrendRow, 0, len(points))
	for _, point := range points {
		v.Rows = append(v.Rows, fleetTrendRow{Date: point.Date.Format(time.DateOnly), TenantPosturePoint: point})
	}
	v.Chart = postureTrendChart(points)

	current := points[len(points)-1]
	v.Stats = []trendStat{
		{Label: "Relevant findings", Value: current.Total},
		{Label: "Critical", Value: current.Critical, Tone: "danger-n"},
		{Label: "High", Value: current.High},
		{Label: "Fixable", Value: current.Fixable, NeutralDelta: true},
		{Label: "KEV", Value: current.KEV, Tone: "kev-n"},
	}
	if len(points) > 1 {
		v.HasPrevious = true
		previous := points[len(points)-2]
		if previous.Date.AddDate(0, 0, 1).Format(time.DateOnly) == current.Date.Format(time.DateOnly) {
			v.ComparisonLabel = "Day-over-day change"
		} else {
			v.ComparisonLabel = "Change since " + previous.Date.Format(time.DateOnly)
		}
		deltas := []int{
			current.Total - previous.Total,
			current.Critical - previous.Critical,
			current.High - previous.High,
			current.Fixable - previous.Fixable,
			current.KEV - previous.KEV,
		}
		for i, delta := range deltas {
			v.Stats[i].DeltaText = signed(delta)
			if v.Stats[i].NeutralDelta {
				v.Stats[i].DeltaClass = "trend-neutral"
			} else {
				v.Stats[i].DeltaClass = trendDeltaClass(delta)
			}
		}
	}
	render(w, "trends.html", v)
}

func trendDays(raw string) int {
	if raw == "" {
		return defaultTrendDays
	}
	days, err := strconv.Atoi(raw)
	if err != nil {
		return defaultTrendDays
	}
	if days < 1 {
		return 1
	}
	if days > 365 {
		return 365
	}
	return days
}

func trendDayOptions(selected int) []trendDayOption {
	values := []int{7, 30, 90, 365}
	options := make([]trendDayOption, 0, len(values)+1)
	hasSelected := false
	for _, value := range values {
		if value == selected {
			hasSelected = true
		}
		options = append(options, trendDayOption{Value: value, Selected: value == selected})
	}
	if !hasSelected {
		options = append(options, trendDayOption{Value: selected, Selected: true})
	}
	return options
}

func trendDeltaClass(delta int) string {
	switch {
	case delta > 0:
		return "trend-up"
	case delta < 0:
		return "trend-down"
	default:
		return "trend-flat"
	}
}

func postureTrendChart(points []postgres.TenantPosturePoint) template.HTML {
	if len(points) == 0 {
		return ""
	}
	const (
		width  = 960
		height = 240
		left   = 58
		right  = 20
		top    = 20
		bottom = 42
	)
	plotWidth, plotHeight := width-left-right, height-top-bottom
	maximum := 0
	for _, point := range points {
		if point.Total > maximum {
			maximum = point.Total
		}
	}
	scaleMaximum := maximum
	if scaleMaximum == 0 {
		scaleMaximum = 1
	}
	first, last := points[0].Date, points[len(points)-1].Date
	span := last.Sub(first).Hours() / 24

	coordinates := make([]string, 0, len(points))
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="chart trend-chart" viewBox="0 0 %d %d" role="img" aria-labelledby="fleet-trend-title fleet-trend-desc">`, width, height)
	fmt.Fprintf(&b, `<title id="fleet-trend-title">Relevant finding debt across %d recorded snapshots</title>`, len(points))
	fmt.Fprintf(&b, `<desc id="fleet-trend-desc">Recorded snapshots from %s through %s. Missing dates are not synthesized; exact values follow in the table.</desc>`,
		first.Format(time.DateOnly), last.Format(time.DateOnly))
	for i := 0; i <= 2; i++ {
		y := top + i*plotHeight/2
		fmt.Fprintf(&b, `<line class="trend-grid" x1="%d" y1="%d" x2="%d" y2="%d"></line>`, left, y, width-right, y)
	}
	fmt.Fprintf(&b, `<text class="chart-val" x="%d" y="%d" text-anchor="end">%d</text>`, left-8, top+4, maximum)
	fmt.Fprintf(&b, `<text class="chart-val" x="%d" y="%d" text-anchor="end">0</text>`, left-8, top+plotHeight+4)

	type chartPoint struct{ x, y int }
	positions := make([]chartPoint, 0, len(points))
	for _, point := range points {
		x := left + plotWidth/2
		if span > 0 {
			x = left + int((point.Date.Sub(first).Hours()/24/span)*float64(plotWidth))
		}
		y := top + plotHeight - point.Total*plotHeight/scaleMaximum
		positions = append(positions, chartPoint{x: x, y: y})
		coordinates = append(coordinates, fmt.Sprintf("%d,%d", x, y))
	}
	if len(coordinates) > 1 {
		fmt.Fprintf(&b, `<polyline class="trend-line" points="%s"></polyline>`, strings.Join(coordinates, " "))
	}
	for i, position := range positions {
		point := points[i]
		fmt.Fprintf(&b, `<circle class="trend-point" cx="%d" cy="%d" r="4"><title>%s: %d findings</title></circle>`,
			position.x, position.y, point.Date.Format(time.DateOnly), point.Total)
	}
	fmt.Fprintf(&b, `<text class="chart-xlbl" x="%d" y="%d">%s</text>`, left, height-12, first.Format(time.DateOnly))
	if len(points) > 1 {
		fmt.Fprintf(&b, `<text class="chart-xlbl" x="%d" y="%d" text-anchor="end">%s</text>`, width-right, height-12, last.Format(time.DateOnly))
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

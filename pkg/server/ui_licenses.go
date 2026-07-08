package server

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/thingzio/devradar/pkg/data"
	"github.com/thingzio/devradar/pkg/middleware"
)

// licensesView is the whole Licenses page model. Charts are pre-rendered inline
// SVG (no client JS), matching the rest of the UI.
type licensesView struct {
	Title    string
	SignedIn bool
	Tab      string
	Email    string
	Version  string
	HasData  bool
	// Headline stats.
	PackageCount int
	Unlicensed   int
	Violations   int
	PolicyActive bool
	// Charts.
	CategoryChart template.HTML // donut: distribution by obligation category
	FamilyChart   template.HTML // treemap: packages by license family
	FamilyLegend  []familyLegendRow
	// Policy settings form.
	Categories   []categoryOption
	AllowExcepts string
	DenyExcepts  string
}

// categoryOption is one selectable license category in the policy form.
type categoryOption struct {
	Key    string
	Label  string
	Denied bool
	Color  string
	Count  int // packages in this category across the fleet
}

// familyLegendRow labels a treemap color for the family legend.
type familyLegendRow struct {
	Label string
	Count int
	Color string
}

// handleLicensesPage renders the Licenses tab: fleet license distribution
// (category donut + family treemap) and the compliance-policy editor.
func (s *Server) handleLicensesPage(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())

	policy, err := s.store.GetLicensePolicy(r.Context(), tn.ID)
	if err != nil {
		http.Error(w, "failed to load policy", http.StatusInternalServerError)
		return
	}
	stats, err := s.store.FleetLicenseStats(r.Context(), tn.ID, policy)
	if err != nil {
		http.Error(w, "failed to load licenses", http.StatusInternalServerError)
		return
	}

	v := licensesView{
		Title: "Licenses", SignedIn: true, Tab: "licenses", Email: tn.Email, Version: s.opts.Version,
		HasData:      stats.Packages > 0,
		PackageCount: stats.Packages,
		Unlicensed:   stats.Unlicensed,
		Violations:   stats.Violations,
		PolicyActive: !policy.IsEmpty(),
		AllowExcepts: strings.Join(policy.AllowExceptions, ", "),
		DenyExcepts:  strings.Join(policy.DenyExceptions, ", "),
	}

	// Category donut.
	catCounts := map[string]int{}
	var catSlices []slice
	for _, c := range stats.Categories {
		catCounts[c.Key] = c.Count
		catSlices = append(catSlices, slice{Label: categoryLabel(c.Key), Value: c.Count, Color: categoryFill(c.Key)})
	}
	v.CategoryChart = donutChart(catSlices, "packages", 200)

	// Family treemap + legend.
	var cells []treeCell
	for _, f := range stats.Families {
		color := familyColor(f.Key)
		cells = append(cells, treeCell{Label: f.Key, Value: f.Count, Color: color})
		v.FamilyLegend = append(v.FamilyLegend, familyLegendRow{Label: f.Key, Count: f.Count, Color: color})
	}
	v.FamilyChart = treemapChart(cells, 460, 300)

	// Policy form options (with fleet counts so the impact of denying is visible).
	denied := map[data.LicenseCategory]struct{}{}
	for _, c := range policy.DeniedCategories {
		denied[c] = struct{}{}
	}
	for _, c := range data.ValidLicenseCategories {
		_, isDenied := denied[c]
		v.Categories = append(v.Categories, categoryOption{
			Key:    string(c),
			Label:  categoryLabel(string(c)),
			Denied: isDenied,
			Color:  categoryFill(string(c)),
			Count:  catCounts[string(c)],
		})
	}

	render(w, "licenses.html", v)
}

// handleSetLicensePolicy persists the tenant's compliance policy from the form
// (mirrors handleSetMinSeverity). Denied categories are checkboxes; exceptions
// are comma/space-separated license-ID lists.
func (s *Server) handleSetLicensePolicy(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	var p data.LicensePolicy
	for _, c := range r.Form["denied"] {
		if data.ValidLicenseCategory(c) {
			p.DeniedCategories = append(p.DeniedCategories, data.LicenseCategory(c))
		}
	}
	p.AllowExceptions = splitLicenseList(r.FormValue("allow_exceptions"))
	p.DenyExceptions = splitLicenseList(r.FormValue("deny_exceptions"))

	if err := s.store.SetLicensePolicy(r.Context(), tn.ID, p); err != nil {
		http.Error(w, "failed to save policy", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/licenses", http.StatusSeeOther)
}

// splitLicenseList parses a comma/whitespace-separated list of license IDs,
// trimming and dropping empties.
func splitLicenseList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// categoryLabel is the human-friendly display label for a category key.
func categoryLabel(key string) string {
	switch key {
	case string(data.CategoryPermissive):
		return "Permissive"
	case string(data.CategoryWeakCopyleft):
		return "Weak copyleft"
	case string(data.CategoryStrongCopyleft):
		return "Strong copyleft"
	case string(data.CategoryProprietary):
		return "Proprietary"
	default:
		return "Unknown"
	}
}

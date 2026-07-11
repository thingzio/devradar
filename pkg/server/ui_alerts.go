package server

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/thingzio/devradar/pkg/alert"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
)

type alertRow struct {
	ID         string
	Title      string
	Kind       string
	Exposure   string
	Repository string
	Severity   string
	Cause      string
	CreatedAt  time.Time
	Unread     bool
}

type alertsView struct {
	Title      string
	SignedIn   bool
	Tab        string
	Email      string
	AvatarURL  string
	Version    string
	Alerts     []alertRow
	NextCursor string
}

type alertDetailView struct {
	Title       string
	SignedIn    bool
	Tab         string
	Email       string
	AvatarURL   string
	Version     string
	CSRFToken   string
	Alert       *postgres.Alert
	AlertTitle  string
	Description string
	CauseLabel  string
	EPSSPercent string
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	items, next, err := s.store.ListAlerts(r.Context(), tn.ID, r.URL.Query().Get("cursor"), 50)
	if err != nil {
		http.Error(w, "failed to load alerts", http.StatusInternalServerError)
		return
	}
	v := alertsView{
		Title: "Alerts", SignedIn: true, Tab: "alerts", Email: tn.Email,
		AvatarURL: tn.AvatarURL, Version: s.opts.Version, NextCursor: next,
	}
	for _, item := range items {
		v.Alerts = append(v.Alerts, makeAlertRow(item))
	}
	render(w, "alerts.html", v)
}

func (s *Server) handleAlertDetail(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	item, err := s.store.GetAlert(r.Context(), tn.ID, r.PathValue("id"))
	if errors.Is(err, postgres.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "failed to load alert", http.StatusInternalServerError)
		return
	}
	v := alertDetailView{
		Title: alertTitle(item.Kind), SignedIn: true, Tab: "alerts", Email: tn.Email,
		AvatarURL: tn.AvatarURL, Version: s.opts.Version, CSRFToken: issueCSRF(w), Alert: item,
		AlertTitle: alertTitle(item.Kind), Description: alertDescription(item.Kind), CauseLabel: alertCause(item.Cause),
	}
	if item.EPSS != nil {
		v.EPSSPercent = fmt.Sprintf("%.1f%%", *item.EPSS*100)
	}
	render(w, "alert.html", v)
}

func (s *Server) handleMarkAlertRead(w http.ResponseWriter, r *http.Request) {
	tn := middleware.TenantFromContext(r.Context())
	id := r.PathValue("id")
	if err := s.store.MarkAlertRead(r.Context(), tn.ID, id); errors.Is(err, postgres.ErrNotFound) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		http.Error(w, "failed to update alert", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/alerts/"+id, http.StatusSeeOther)
}

func makeAlertRow(item postgres.Alert) alertRow {
	return alertRow{
		ID: item.ID, Title: alertTitle(item.Kind), Kind: item.Kind, Exposure: item.Exposure,
		Repository: item.Repository, Severity: item.Severity, Cause: alertCause(item.Cause),
		CreatedAt: item.CreatedAt, Unread: item.ReadAt == nil,
	}
}

func alertTitle(kind string) string {
	switch kind {
	case alert.KindNewKEV:
		return "Known exploited vulnerability"
	case alert.KindFixAvailable:
		return "Fix now available"
	case alert.KindPostureRegression:
		return "Posture regression"
	default:
		return "New vulnerability"
	}
}

func alertDescription(kind string) string {
	switch kind {
	case alert.KindNewKEV:
		return "CISA lists this vulnerability as known to be exploited."
	case alert.KindFixAvailable:
		return "A scanner now reports that a fix is available for this finding."
	case alert.KindPostureRegression:
		return "A tracked image generation has a worse observed vulnerability posture."
	default:
		return "A scanner reported a new vulnerability that matches your alert settings."
	}
}

func alertCause(cause string) string {
	if cause == "image" {
		return "Image inventory"
	}
	return "Vulnerability database"
}

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

package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
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
	chromeView
	Alerts     []alertRow
	NextCursor string
}

type alertDetailView struct {
	chromeView
	CSRFToken             string
	Alert                 *postgres.Alert
	AlertTitle            string
	Description           string
	CauseLabel            string
	EPSSPercent           string
	WorkURL               string
	PreviousComparisonURL string
	RecommendationURL     string
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	items, next, err := s.store.ListAlerts(r.Context(), access.Account.ID, access.Actor.ID,
		r.URL.Query().Get("cursor"), 50)
	if err != nil {
		slog.Error("list personal alerts", "account_id", access.Account.ID,
			"user_id", access.Actor.ID, "request_id", middleware.RequestIDFromContext(r.Context()), "error", err)
		http.Error(w, "failed to load alerts", http.StatusInternalServerError)
		return
	}
	v := alertsView{
		chromeView: s.chrome(access, "Alerts", "alerts"), NextCursor: next,
	}
	for _, item := range items {
		v.Alerts = append(v.Alerts, makeAlertRow(item))
	}
	render(w, "alerts.html", v)
}

func (s *Server) handleAlertDetail(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	item, err := s.store.GetAlert(r.Context(), access.Account.ID, access.Actor.ID, r.PathValue("id"))
	if errors.Is(err, postgres.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		slog.Error("load personal alert", "account_id", access.Account.ID,
			"user_id", access.Actor.ID, "alert_id", r.PathValue("id"),
			"request_id", middleware.RequestIDFromContext(r.Context()), "error", err)
		http.Error(w, "failed to load alert", http.StatusInternalServerError)
		return
	}
	v := alertDetailView{
		chromeView: s.chrome(access, alertTitle(item.Kind), "alerts"), CSRFToken: issueCSRF(w), Alert: item,
		AlertTitle: alertTitle(item.Kind), Description: alertDescription(item.Kind), CauseLabel: alertCause(item.Cause),
		WorkURL: "/work#work-" + url.PathEscape(item.Exposure),
	}
	if item.EPSS != nil {
		v.EPSSPercent = fmt.Sprintf("%.1f%%", *item.EPSS*100)
	}
	comparison, err := s.store.ComparePreviousSBOM(r.Context(), access.Account.ID, item.SBOMID)
	if err != nil {
		slog.Warn("load alert preceding comparison", "account_id", access.Account.ID, "alert_id", item.ID, "sbom_id", item.SBOMID, "error", err)
	} else if comparison != nil {
		v.PreviousComparisonURL = "/compare?" + url.Values{
			"from": {comparison.From.SBOMID},
			"to":   {comparison.To.SBOMID},
		}.Encode()
	}
	recommendation, err := s.store.RecommendUpgrade(r.Context(), access.Account.ID, item.SBOMID)
	if err != nil {
		slog.Warn("load alert upgrade recommendation", "account_id", access.Account.ID, "alert_id", item.ID, "sbom_id", item.SBOMID, "error", err)
	} else if recommendation != nil {
		v.RecommendationURL = "/compare?" + url.Values{
			"from": {recommendation.Baseline.SBOMID},
			"to":   {recommendation.Candidate.SBOMID},
		}.Encode()
	}
	render(w, "alert.html", v)
}

func (s *Server) handleMarkAlertRead(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	id := r.PathValue("id")
	if err := s.store.MarkAlertRead(r.Context(), access.Account.ID, access.Actor.ID, id); errors.Is(err, postgres.ErrNotFound) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		slog.Error("mark personal alert read", "account_id", access.Account.ID,
			"user_id", access.Actor.ID, "alert_id", id,
			"request_id", middleware.RequestIDFromContext(r.Context()), "error", err)
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

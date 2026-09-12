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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thingzio/devradar/pkg/claude"
	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/middleware"
)

// The admin metrics page queries GCP Cloud Monitoring for the serve service and
// the scan job, renders the raw series, and — when an Anthropic API key is
// configured — prepends a short Claude-generated health analysis. The AI summary
// is optional: with no key the page still renders the raw series.

const (
	analysisMaxTokens = 1024
	analysisTimeout   = 30 * time.Second
)

// metricsAnalysisPrompt frames Claude as a health advisor for the operator.
const metricsAnalysisPrompt = `You are a site-reliability advisor for DevRadar, a container-vulnerability
SaaS on Google Cloud Run. It has two components: a serve service (ingest + read API + UI) and a scan
job (a scheduled Cloud Run Job that rescans SBOMs with Grype and Trivy). You are given raw Cloud
Monitoring time series for both. In 3-5 sentences, plain text (no markdown), tell the operator what
the numbers say about health: call out elevated error rates, latency, saturation, or a scan job that
is failing or not running. If everything looks nominal, say so plainly. Do not restate every metric —
surface only what the operator should act on or be reassured by.`

const (
	monitoringBaseURL  = "https://monitoring.googleapis.com/v3/projects"
	metadataTokenURL   = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" //nolint:gosec // GCP metadata URL, not a credential
	metadataProjectURL = "http://metadata.google.internal/computeMetadata/v1/project/project-id"
	metricsHTTPTimeout = 10 * time.Second
	metricsHandlerTO   = 45 * time.Second
	defaultMetricDays  = 1
	maxMetricDays      = 30
)

var (
	metricsHTTPClient = &http.Client{Timeout: metricsHTTPTimeout}
	metricDayOptions  = []int{1, 2, 7, 14, 30}
)

// adminMetricsConfig names the GCP project, Cloud Run resources, and Cloud SQL
// instance to query. nil (from newAdminMetricsConfig) means "no project" → the
// page shows a disabled state instead of erroring.
type adminMetricsConfig struct {
	projectID string
	service   string // Cloud Run service (serve)
	job       string // Cloud Run job (scan)
	database  string // Cloud SQL instance
}

func newAdminMetricsConfig() *adminMetricsConfig {
	projectID := config.GetEnv("GCP_PROJECT_ID", "")
	if projectID == "" {
		projectID = gcpMetadataProjectID()
	}
	if projectID == "" {
		return nil
	}
	// K_SERVICE is auto-set by Cloud Run to the running service name.
	service := config.GetEnv("K_SERVICE", config.GetEnv("DEVRADAR_SERVICE_NAME", "devradar-saas-serve"))
	job := config.GetEnv("DEVRADAR_SCAN_JOB_NAME", "devradar-saas-scan")
	database := config.GetEnv("DEVRADAR_CLOUD_SQL_INSTANCE", "thingzio-pg")
	return &adminMetricsConfig{projectID: projectID, service: service, job: job, database: database}
}

// handleAdminMetrics renders GCP Cloud Monitoring series for the serve service
// and scan job. Disabled (informational) when no GCP project is resolvable.
func (s *Server) handleAdminMetrics(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	auditLog("view_metrics", user, r.URL.Path, r.RemoteAddr, "")

	cfg := newAdminMetricsConfig()
	if cfg == nil {
		render(w, "admin_metrics.html", s.adminBase(user, "metrics", map[string]any{
			"Title":    "Admin — Metrics",
			"Disabled": true,
		}))
		return
	}

	days := clampInt(r.URL.Query().Get("days"), defaultMetricDays, maxMetricDays)

	ctx, cancel := context.WithTimeout(r.Context(), metricsHandlerTO)
	defer cancel()

	var raw string
	token, err := gcpMetadataToken(ctx)
	if err != nil {
		raw = "Unable to obtain a GCP access token (not running on GCP, or missing monitoring scope):\n  " + err.Error()
	} else {
		raw = collectGCPMetrics(ctx, cfg, token, days)
	}

	// Optional Claude health analysis. Nil client (no API key) → skipped silently;
	// on error we surface a short note but still render the raw series.
	analysis, analysisErr := analyzeMetrics(r.Context(), raw)

	render(w, "admin_metrics.html", s.adminBase(user, "metrics", map[string]any{
		"Title":       "Admin — Metrics",
		"Disabled":    false,
		"ProjectID":   cfg.projectID,
		"Days":        days,
		"DayOptions":  metricDayOptions,
		"RawMetrics":  raw,
		"Analysis":    analysis,
		"AnalysisErr": analysisErr,
	}))
}

// analyzeMetrics asks Claude (Haiku) for a short health read on the raw series.
// Returns ("", "") when no API key is configured (feature simply absent), or
// ("", <note>) on an API error so the page can explain the empty analysis.
func analyzeMetrics(ctx context.Context, raw string) (analysis, note string) {
	c := claude.New()
	if !c.Available() {
		return "", ""
	}
	actx, cancel := context.WithTimeout(ctx, analysisTimeout)
	defer cancel()
	out, err := c.Summarize(actx, metricsAnalysisPrompt, raw, analysisMaxTokens)
	if err != nil {
		return "", "AI analysis unavailable: " + err.Error()
	}
	return out, ""
}

func gcpMetadataProjectID() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataProjectURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := metricsHTTPClient.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

func gcpMetadataToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataTokenURL, nil)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := metricsHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata server returned %d", resp.StatusCode)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", fmt.Errorf("decode token: %w", err)
	}
	return tok.AccessToken, nil
}

type metricQuery struct {
	label  string
	filter string
	params string
}

func adminMetricQueries(cfg *adminMetricsConfig) []metricQuery {
	align := "aggregation.alignmentPeriod=3600s"
	svc, job := cfg.service, cfg.job
	databaseID := cfg.projectID + ":" + cfg.database
	return []metricQuery{
		{
			label:  "serve: request count (req/s by response class)",
			filter: fmt.Sprintf(`resource.type="cloud_run_revision" AND resource.labels.service_name="%s" AND metric.type="run.googleapis.com/request_count"`, svc),
			params: align + "&aggregation.perSeriesAligner=ALIGN_RATE&aggregation.crossSeriesReducer=REDUCE_SUM&aggregation.groupByFields=metric.labels.response_code_class",
		},
		{
			label:  "serve: request latency p99 (ms)",
			filter: fmt.Sprintf(`resource.type="cloud_run_revision" AND resource.labels.service_name="%s" AND metric.type="run.googleapis.com/request_latencies"`, svc),
			params: align + "&aggregation.perSeriesAligner=ALIGN_PERCENTILE_99&aggregation.crossSeriesReducer=REDUCE_MEAN",
		},
		{
			label:  "serve: instance count",
			filter: fmt.Sprintf(`resource.type="cloud_run_revision" AND resource.labels.service_name="%s" AND metric.type="run.googleapis.com/container/instance_count"`, svc),
			params: align + "&aggregation.perSeriesAligner=ALIGN_MAX&aggregation.crossSeriesReducer=REDUCE_SUM",
		},
		{
			label:  "serve: CPU utilization p95",
			filter: fmt.Sprintf(`resource.type="cloud_run_revision" AND resource.labels.service_name="%s" AND metric.type="run.googleapis.com/container/cpu/utilizations"`, svc),
			params: align + "&aggregation.perSeriesAligner=ALIGN_PERCENTILE_95&aggregation.crossSeriesReducer=REDUCE_MEAN",
		},
		{
			label:  "serve: memory utilization p95",
			filter: fmt.Sprintf(`resource.type="cloud_run_revision" AND resource.labels.service_name="%s" AND metric.type="run.googleapis.com/container/memory/utilizations"`, svc),
			params: align + "&aggregation.perSeriesAligner=ALIGN_PERCENTILE_95&aggregation.crossSeriesReducer=REDUCE_MEAN",
		},
		{
			label:  "scan job: completed executions (by result)",
			filter: fmt.Sprintf(`resource.type="cloud_run_job" AND resource.labels.job_name="%s" AND metric.type="run.googleapis.com/job/completed_execution_count"`, job),
			params: align + "&aggregation.perSeriesAligner=ALIGN_SUM&aggregation.crossSeriesReducer=REDUCE_SUM&aggregation.groupByFields=metric.labels.result",
		},
		{
			label:  "scan job: running executions",
			filter: fmt.Sprintf(`resource.type="cloud_run_job" AND resource.labels.job_name="%s" AND metric.type="run.googleapis.com/job/running_executions"`, job),
			params: align + "&aggregation.perSeriesAligner=ALIGN_MAX&aggregation.crossSeriesReducer=REDUCE_SUM",
		},
		{
			label:  "database: CPU utilization",
			filter: fmt.Sprintf(`resource.type="cloudsql_database" AND resource.labels.database_id="%s" AND metric.type="cloudsql.googleapis.com/database/cpu/utilization"`, databaseID),
			params: align + "&aggregation.perSeriesAligner=ALIGN_MEAN",
		},
		{
			label:  "database: active connections",
			filter: fmt.Sprintf(`resource.type="cloudsql_database" AND resource.labels.database_id="%s" AND metric.labels.state="active" AND metric.type="cloudsql.googleapis.com/database/postgresql/num_backends_by_state"`, databaseID),
			params: align + "&aggregation.perSeriesAligner=ALIGN_MAX",
		},
		{
			label:  "database: disk utilization",
			filter: fmt.Sprintf(`resource.type="cloudsql_database" AND resource.labels.database_id="%s" AND metric.type="cloudsql.googleapis.com/database/disk/utilization"`, databaseID),
			params: align + "&aggregation.perSeriesAligner=ALIGN_MAX",
		},
	}
}

type queryResult struct {
	label string
	body  string
	err   error
}

func fetchQueries(ctx context.Context, projectID, token string, queries []metricQuery, start, end time.Time) []queryResult {
	results := make([]queryResult, len(queries))
	var wg sync.WaitGroup
	wg.Add(len(queries))
	for i, q := range queries {
		go func(idx int, mq metricQuery) {
			defer wg.Done()
			raw, err := queryTimeSeries(ctx, projectID, token, mq.filter, mq.params, start, end)
			results[idx] = queryResult{label: mq.label, body: raw, err: err}
		}(i, q)
	}
	wg.Wait()
	return results
}

func collectGCPMetrics(ctx context.Context, cfg *adminMetricsConfig, token string, days int) string {
	now := time.Now().UTC()
	start := now.Add(-time.Duration(days) * 24 * time.Hour)

	var b strings.Builder
	fmt.Fprintf(&b, "DevRadar Cloud Metrics — last %d day(s), project %s, %s\n",
		days, cfg.projectID, now.Format("2006-01-02 15:04 UTC"))
	b.WriteString("NOTE: Cloud Run service metrics are service-wide; this page's own requests are included.\n\n")

	for _, r := range fetchQueries(ctx, cfg.projectID, token, adminMetricQueries(cfg), start, now) {
		if r.err != nil {
			fmt.Fprintf(&b, "--- %s ---\n  (error: %s)\n\n", r.label, r.err)
			continue
		}
		fmt.Fprintf(&b, "--- %s ---\n%s\n\n", r.label, formatTimeSeries(r.body))
	}
	return b.String()
}

func queryTimeSeries(ctx context.Context, projectID, token, filter, params string, start, end time.Time) (string, error) {
	u := fmt.Sprintf("%s/%s/timeSeries?filter=%s&interval.startTime=%s&interval.endTime=%s&%s",
		monitoringBaseURL, projectID, url.QueryEscape(filter),
		start.Format(time.RFC3339), end.Format(time.RFC3339), params)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil) //nolint:gosec // URL from trusted config
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := metricsHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("query metrics: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("monitoring API returned %d: %s", resp.StatusCode, string(body[:min(len(body), 200)]))
	}
	return string(body), nil
}

// formatTimeSeries reduces the monitoring API JSON to a compact per-series line
// (up to the first 8 points), mirroring the sibling services' rendering.
func formatTimeSeries(raw string) string {
	var resp struct {
		TimeSeries []struct {
			Metric struct {
				Labels map[string]string `json:"labels"`
			} `json:"metric"`
			Points []struct {
				Interval struct {
					StartTime string `json:"startTime"`
				} `json:"interval"`
				Value struct {
					DoubleValue *float64 `json:"doubleValue"`
					Int64Value  *string  `json:"int64Value"`
				} `json:"value"`
			} `json:"points"`
		} `json:"timeSeries"`
	}
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		return "  (parse error)"
	}
	if len(resp.TimeSeries) == 0 {
		return "  (no data)"
	}
	var b strings.Builder
	for _, ts := range resp.TimeSeries {
		var prefix string
		if len(ts.Metric.Labels) > 0 {
			var parts []string
			for _, v := range ts.Metric.Labels {
				parts = append(parts, v)
			}
			prefix = strings.Join(parts, " ") + ": "
		}
		limit := min(8, len(ts.Points))
		var vals []string
		for _, p := range ts.Points[:limit] {
			t := p.Interval.StartTime
			if len(t) > 16 {
				t = t[5:16]
			}
			var v float64
			if p.Value.DoubleValue != nil {
				v = *p.Value.DoubleValue
			} else if p.Value.Int64Value != nil {
				if iv, err := strconv.ParseFloat(*p.Value.Int64Value, 64); err == nil {
					v = iv
				}
			}
			vals = append(vals, fmt.Sprintf("%s=%.2f", t, v))
		}
		fmt.Fprintf(&b, "  %s%s\n", prefix, strings.Join(vals, ", "))
	}
	return b.String()
}

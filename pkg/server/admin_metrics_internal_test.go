package server

import (
	"strings"
	"testing"
)

func TestAdminMetricsConfig(t *testing.T) {
	t.Setenv("GCP_PROJECT_ID", "project-test")
	t.Setenv("K_SERVICE", "")
	t.Setenv("DEVRADAR_SERVICE_NAME", "serve-test")
	t.Setenv("DEVRADAR_SCAN_JOB_NAME", "scan-test")
	t.Setenv("DEVRADAR_CLOUD_SQL_INSTANCE", "sql-test")

	cfg := newAdminMetricsConfig()
	if cfg == nil {
		t.Fatal("newAdminMetricsConfig() = nil")
	}
	if cfg.projectID != "project-test" || cfg.service != "serve-test" || cfg.job != "scan-test" || cfg.database != "sql-test" {
		t.Fatalf("admin metrics config = %+v", cfg)
	}

	t.Setenv("DEVRADAR_CLOUD_SQL_INSTANCE", "")
	cfg = newAdminMetricsConfig()
	if cfg == nil || cfg.database != "thingzio-pg" {
		t.Fatalf("default database config = %+v, want thingzio-pg", cfg)
	}
}

func TestAdminMetricQueries(t *testing.T) {
	cfg := &adminMetricsConfig{
		projectID: "project-test",
		service:   "serve-test",
		job:       "scan-test",
		database:  "sql-test",
	}
	queries := adminMetricQueries(cfg)
	if len(queries) != 10 {
		t.Fatalf("admin metric query count = %d, want 10", len(queries))
	}

	for _, want := range []string{
		`run.googleapis.com/request_count`,
		`run.googleapis.com/request_latencies`,
		`run.googleapis.com/container/instance_count`,
		`run.googleapis.com/job/completed_execution_count`,
		`run.googleapis.com/job/running_executions`,
	} {
		if findMetricQuery(queries, want) == nil {
			t.Errorf("missing existing metric query %q", want)
		}
	}

	tests := []struct {
		metric   string
		resource string
		identity string
		aligner  string
		reducer  string
	}{
		{
			metric:   `run.googleapis.com/container/cpu/utilizations`,
			resource: `resource.type="cloud_run_revision"`,
			identity: `resource.labels.service_name="serve-test"`,
			aligner:  `aggregation.perSeriesAligner=ALIGN_PERCENTILE_95`,
			reducer:  `aggregation.crossSeriesReducer=REDUCE_MEAN`,
		},
		{
			metric:   `run.googleapis.com/container/memory/utilizations`,
			resource: `resource.type="cloud_run_revision"`,
			identity: `resource.labels.service_name="serve-test"`,
			aligner:  `aggregation.perSeriesAligner=ALIGN_PERCENTILE_95`,
			reducer:  `aggregation.crossSeriesReducer=REDUCE_MEAN`,
		},
		{
			metric:   `cloudsql.googleapis.com/database/cpu/utilization`,
			resource: `resource.type="cloudsql_database"`,
			identity: `resource.labels.database_id="project-test:sql-test"`,
			aligner:  `aggregation.perSeriesAligner=ALIGN_MEAN`,
		},
		{
			metric:   `cloudsql.googleapis.com/database/postgresql/num_backends_by_state`,
			resource: `resource.type="cloudsql_database"`,
			identity: `resource.labels.database_id="project-test:sql-test" AND metric.labels.state="active"`,
			aligner:  `aggregation.perSeriesAligner=ALIGN_MAX`,
		},
		{
			metric:   `cloudsql.googleapis.com/database/disk/utilization`,
			resource: `resource.type="cloudsql_database"`,
			identity: `resource.labels.database_id="project-test:sql-test"`,
			aligner:  `aggregation.perSeriesAligner=ALIGN_MAX`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.metric, func(t *testing.T) {
			query := findMetricQuery(queries, tc.metric)
			if query == nil {
				t.Fatalf("missing metric query %q", tc.metric)
			}
			for _, want := range []string{tc.resource, tc.identity, `metric.type="` + tc.metric + `"`} {
				if !strings.Contains(query.filter, want) {
					t.Errorf("filter %q missing %q", query.filter, want)
				}
			}
			for _, want := range []string{
				"aggregation.alignmentPeriod=3600s",
				tc.aligner,
				tc.reducer,
			} {
				if want != "" && !strings.Contains(query.params, want) {
					t.Errorf("params %q missing %q", query.params, want)
				}
			}
		})
	}
}

func findMetricQuery(queries []metricQuery, metric string) *metricQuery {
	for i := range queries {
		if strings.Contains(queries[i].filter, `metric.type="`+metric+`"`) {
			return &queries[i]
		}
	}
	return nil
}

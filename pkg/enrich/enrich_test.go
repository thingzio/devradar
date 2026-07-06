package enrich

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetch_MergesKEVandEPSS(t *testing.T) {
	kevJSON := `{"vulnerabilities":[
		{"cveID":"CVE-2025-0001","dateAdded":"2025-01-15"},
		{"cveID":"CVE-2025-0002","dateAdded":"2025-02-20"}]}`
	// EPSS echoes back whatever CVEs are asked for (via ?cve=).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "known_exploited"):
			_, _ = w.Write([]byte(kevJSON))
		default: // EPSS
			q := r.URL.Query().Get("cve")
			data := ""
			for c := range strings.SplitSeq(q, ",") {
				if c == "CVE-2025-0001" {
					data += `{"cve":"CVE-2025-0001","epss":"0.94210","percentile":"0.99000"},`
				}
				if c == "CVE-2025-0003" {
					data += `{"cve":"CVE-2025-0003","epss":"0.00120","percentile":"0.40000"},`
				}
			}
			data = strings.TrimSuffix(data, ",")
			_, _ = w.Write([]byte(`{"data":[` + data + `]}`))
		}
	}))
	defer srv.Close()

	f := &Fetcher{
		KEVURL:     srv.URL + "/known_exploited_vulnerabilities.json",
		EPSSAPIURL: srv.URL + "/epss",
		Client:     srv.Client(),
	}
	recs, err := f.Fetch(context.Background(), []string{"CVE-2025-0001", "CVE-2025-0003"})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	byCVE := map[string]Record{}
	for _, r := range recs {
		byCVE[r.CVE] = r
	}

	// 0001: KEV + EPSS both present.
	r1 := byCVE["CVE-2025-0001"]
	if !r1.KEV || r1.KEVAdded != "2025-01-15" {
		t.Errorf("0001 KEV = %v/%q, want true/2025-01-15", r1.KEV, r1.KEVAdded)
	}
	if r1.EPSSScore == nil || *r1.EPSSScore < 0.9 {
		t.Errorf("0001 EPSS = %v, want ~0.94", r1.EPSSScore)
	}

	// 0002: KEV only (not in the requested EPSS set, but a KEV hit is always kept).
	if r := byCVE["CVE-2025-0002"]; !r.KEV || r.EPSSScore != nil {
		t.Errorf("0002 = %+v, want KEV-only", r)
	}

	// 0003: EPSS only, no KEV.
	r3 := byCVE["CVE-2025-0003"]
	if r3.KEV || r3.EPSSScore == nil {
		t.Errorf("0003 = %+v, want EPSS-only non-KEV", r3)
	}
}

func TestFetch_BothFeedsDownIsError(t *testing.T) {
	f := &Fetcher{
		KEVURL:     "http://127.0.0.1:0/nope",
		EPSSAPIURL: "http://127.0.0.1:0/nope",
		Client:     &http.Client{},
	}
	if _, err := f.Fetch(context.Background(), []string{"CVE-2025-0001"}); err == nil {
		t.Error("expected error when both feeds are unreachable")
	}
}

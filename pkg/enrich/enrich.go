// Package enrich fetches CVE risk context from authoritative public feeds —
// CISA KEV (known-exploited) and FIRST.org EPSS (exploit probability) — and
// merges them into per-CVE records. It is an overlay on the deterministic scan
// pipeline: enrichment is joined into findings at read time, never written into
// devradar_finding, so "same SBOM + same DB -> same findings" still holds.
//
// Feeds are keyed by CVE and refresh daily, matching the scan job's cadence.
// Network failures are the caller's to log/record; a stale enrichment is
// acceptable where a missed scan is not.
package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	// KEVURL is CISA's Known Exploited Vulnerabilities catalog (JSON, ~1300 CVEs).
	KEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	// EPSSAPIURL is FIRST.org's EPSS query API; we request specific CVEs in batches.
	EPSSAPIURL = "https://api.first.org/data/v1/epss"

	// epssBatch bounds how many CVEs go in one EPSS request URL.
	epssBatch      = 100
	fetchTimeout   = 60 * time.Second
	defaultTimeout = 30 * time.Second
	// maxFeedResponseBytes caps a single EPSS/KEV feed response read into memory.
	maxFeedResponseBytes = 64 << 20
)

// Record is the merged enrichment for one CVE. Zero values mean "no data":
// EPSS pointers are nil when EPSS has no entry, KEV is false when absent.
type Record struct {
	CVE            string
	EPSSScore      *float32
	EPSSPercentile *float32
	KEV            bool
	KEVAdded       string // CISA date_added, "YYYY-MM-DD"; empty if not KEV
}

// Fetcher retrieves and merges enrichment. Its URLs and HTTP client are fields
// so tests can point them at fixtures.
type Fetcher struct {
	KEVURL     string
	EPSSAPIURL string
	Client     *http.Client
}

// New returns a Fetcher pointed at the production feeds.
func New() *Fetcher {
	return &Fetcher{
		KEVURL:     KEVURL,
		EPSSAPIURL: EPSSAPIURL,
		Client:     &http.Client{Timeout: fetchTimeout},
	}
}

// Fetch returns enrichment records for the given CVEs. KEV is fetched once (the
// whole catalog); EPSS is requested only for cves (batched). A CVE with neither
// KEV nor EPSS data yields no record — callers upsert what they get. Partial
// failure is surfaced as an error only when nothing could be retrieved.
//
// kevAuthoritative reports whether the KEV catalog was successfully fetched this
// call. It is CRITICAL for the upsert: when false (a KEV feed outage while EPSS
// succeeded), every record carries the zero-value KEV=false, and the store must
// NOT let that clear a previously-set KEV flag — a KEV designation is a
// security-relevant signal that must survive a transient feed blip. Only an
// authoritative fetch may clear a KEV flag (the CVE genuinely left the catalog).
func (f *Fetcher) Fetch(ctx context.Context, cves []string) (recs []Record, kevAuthoritative bool, err error) {
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}

	kev, kevErr := f.fetchKEV(ctx, client)
	epss, epssErr := f.fetchEPSS(ctx, client, cves)
	if kevErr != nil && epssErr != nil {
		return nil, false, fmt.Errorf("enrichment fetch failed: %w", errors.Join(kevErr, epssErr))
	}

	// Merge over the union of CVEs we have data for, restricted to the requested
	// set plus every KEV CVE (a KEV hit is always worth recording).
	want := make(map[string]struct{}, len(cves))
	for _, c := range cves {
		want[c] = struct{}{}
	}
	merged := map[string]*Record{}
	rec := func(cve string) *Record {
		if r, ok := merged[cve]; ok {
			return r
		}
		r := &Record{CVE: cve}
		merged[cve] = r
		return r
	}
	// When the KEV catalog was authoritatively fetched, emit a record for EVERY
	// requested CVE — even those with no EPSS and no KEV entry. This is what lets a
	// KEV DE-listing CONVERGE: a CVE that dropped out of the catalog gets an
	// explicit KEV=false record that the (authoritative) upsert applies, clearing
	// the stale true. Without this, a de-listed CVE with no EPSS row produced no
	// record and kept its old KEV=true forever. On a KEV outage we skip this (no
	// record for a bare CVE) so we never write spurious false during a blip.
	if kevAuthoritative := kevErr == nil; kevAuthoritative {
		for cve := range want {
			_ = rec(cve) // KEV defaults false, KEVAdded empty → clears stale flag
		}
	}
	for cve, added := range kev {
		r := rec(cve)
		r.KEV = true
		r.KEVAdded = added
	}
	for cve, e := range epss {
		if _, ok := want[cve]; !ok {
			continue
		}
		r := rec(cve)
		score, pct := e.score, e.percentile
		r.EPSSScore, r.EPSSPercentile = &score, &pct
	}

	out := make([]Record, 0, len(merged))
	for _, r := range merged {
		out = append(out, *r)
	}
	return out, kevErr == nil, nil
}

// ── KEV ─────────────────────────────────────────────────────────────────────

type kevCatalog struct {
	Vulnerabilities []struct {
		CveID     string `json:"cveID"`
		DateAdded string `json:"dateAdded"`
	} `json:"vulnerabilities"`
}

// fetchKEV returns a map of CVE -> date_added for the whole KEV catalog.
func (f *Fetcher) fetchKEV(ctx context.Context, client *http.Client) (map[string]string, error) {
	body, err := get(ctx, client, f.KEVURL)
	if err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	var cat kevCatalog
	if err := json.Unmarshal(body, &cat); err != nil {
		return nil, fmt.Errorf("kev parse: %w", err)
	}
	out := make(map[string]string, len(cat.Vulnerabilities))
	for _, v := range cat.Vulnerabilities {
		if v.CveID != "" {
			out[v.CveID] = v.DateAdded
		}
	}
	return out, nil
}

// ── EPSS ────────────────────────────────────────────────────────────────────

type epssEntry struct {
	score      float32
	percentile float32
}

type epssResponse struct {
	Data []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
	} `json:"data"`
}

// cveIDPattern matches a well-formed CVE id. CVE strings originate from scanner
// output over attacker-controllable SBOMs, so validate before putting them in a
// request URL.
var cveIDPattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// fetchEPSS requests EPSS for the given CVEs in batches and merges the results.
func (f *Fetcher) fetchEPSS(ctx context.Context, client *http.Client, cves []string) (map[string]epssEntry, error) {
	// Drop anything that isn't a syntactically valid CVE id: it can't have EPSS
	// data and a crafted value must never corrupt the request URL.
	valid := make([]string, 0, len(cves))
	for _, c := range cves {
		if cveIDPattern.MatchString(c) {
			valid = append(valid, c)
		}
	}
	cves = valid

	out := map[string]epssEntry{}
	var firstErr error
	for start := 0; start < len(cves); start += epssBatch {
		end := min(start+epssBatch, len(cves))
		q := url.Values{"cve": {strings.Join(cves[start:end], ",")}}
		reqURL := f.EPSSAPIURL + "?" + q.Encode()
		body, err := get(ctx, client, reqURL)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue // partial: keep what other batches return
		}
		var resp epssResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("epss parse: %w", err)
			}
			continue
		}
		for _, d := range resp.Data {
			out[d.CVE] = epssEntry{
				score:      parseFloat(d.EPSS),
				percentile: parseFloat(d.Percentile),
			}
		}
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func get(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	// Bound the response: a misbehaving, redirected, or MITM'd feed endpoint must
	// not OOM the scan job. The KEV catalog and an EPSS batch are a few MB each;
	// this cap is far above that.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxFeedResponseBytes {
		return nil, fmt.Errorf("GET %s: response exceeds %d bytes", url, maxFeedResponseBytes)
	}
	return body, nil
}

func parseFloat(s string) float32 {
	var f float64
	if _, err := fmt.Sscanf(s, "%g", &f); err != nil {
		return 0
	}
	return float32(f)
}

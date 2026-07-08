package data

// Severity ordering and threshold logic — the single source of truth for "is
// this finding at least as severe as the tenant's minimum of interest".
//
// unknown is deliberately outside the ranked scale: a CVE with no rating could
// be anything, so it is ALWAYS surfaced regardless of the threshold (security-
// conservative — never hide an unrated exposure).

// severityRank maps ranked severities to a comparable integer. unknown is not
// here on purpose (see MeetsThreshold).
var severityRank = map[string]int{
	SeverityCritical:   5,
	SeverityHigh:       4,
	SeverityMedium:     3,
	SeverityLow:        2,
	SeverityNegligible: 1,
}

// DefaultMinSeverity is the tenant default when unset.
const DefaultMinSeverity = SeverityMedium

// ValidMinSeverity reports whether s is a severity a tenant may set as their
// threshold. unknown is not a valid threshold (it's always included, never a
// floor).
func ValidMinSeverity(s string) bool {
	_, ok := severityRank[s]
	return ok
}

// MeetsThreshold reports whether a finding of severity sev should be shown given
// the minimum severity of interest min. unknown always passes. An unrecognized
// sev is treated like unknown (surfaced) rather than silently dropped.
func MeetsThreshold(sev, min string) bool {
	if sev == SeverityUnknown {
		return true
	}
	r, ok := severityRank[sev]
	if !ok {
		return true // unrecognized → surface, don't hide
	}
	minRank, ok := severityRank[min]
	if !ok {
		minRank = severityRank[DefaultMinSeverity]
	}
	return r >= minRank
}

// AllowedSeverities returns the severity strings at or above min, always
// including unknown. Suitable for a SQL `severity = ANY($1)` filter. This is the
// default read-API behavior — an unrated exposure is never hidden.
func AllowedSeverities(min string) []string {
	return allowedSeverities(min, true)
}

// AllowedSeveritiesStrict is like AllowedSeverities but does NOT force-include
// unknown: only ranked severities at or above min are returned. Use where a
// severity filter should mean exactly what it says — e.g. the UI change log,
// where always surfacing unrated rows makes the filter look inert.
func AllowedSeveritiesStrict(min string) []string {
	return allowedSeverities(min, false)
}

func allowedSeverities(min string, includeUnknown bool) []string {
	minRank, ok := severityRank[min]
	if !ok {
		minRank = severityRank[DefaultMinSeverity]
	}
	out := make([]string, 0, len(severityRank)+1)
	for sev, r := range severityRank {
		if r >= minRank {
			out = append(out, sev)
		}
	}
	if includeUnknown {
		out = append(out, SeverityUnknown) // always surfaced
	}
	return out
}

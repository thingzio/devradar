package sbom

import (
	"strings"

	"github.com/Jeffail/gabs/v2"
	"github.com/thingzio/devradar/pkg/data"
)

// maxPackages bounds the number of components we extract from one SBOM. The body
// is already size-capped upstream (20 MiB), but a pathological document could
// still enumerate an enormous component list; this keeps the ingest write bounded
// and predictable. nginx's Syft SBOM has ~3.4k components, so the cap is generous.
const maxPackages = 100_000

// ExtractPackages walks the SBOM's component/package list and returns the
// per-package license inventory. It never converts and never fails closed: a
// document with no components (or an unrecognized format) yields an empty slice,
// not an error, because license capture is additive to ingest — a weak license
// block must never block SBOM storage. The subject-digest path (Resolve) remains
// the authority on whether an SBOM is ingestable at all.
//
// The full license set per package is preserved (deduped, trimmed) — multi-
// license packages and SPDX expressions are kept verbatim so classification and
// policy evaluation happen faithfully at read time.
func ExtractPackages(raw []byte) []data.PackageLicense {
	c, err := gabs.ParseJSON(raw)
	if err != nil {
		return nil
	}
	switch detect(c) {
	case FormatCycloneDX:
		return extractCycloneDXPackages(c)
	case FormatSPDX:
		return extractSPDXPackages(c)
	default:
		return nil
	}
}

// extractCycloneDXPackages reads components[].{name,version,purl,licenses[]}.
// Each licenses[] entry is one of: {license:{id}}, {license:{name}}, or
// {expression}. All three are captured as-is.
//
// Syft's CycloneDX also emits a `file` component per catalogued file (thousands
// per image) — those are not packages and would drown the real dependency
// inventory, so they are skipped. Everything else (library, application,
// operating-system, …) is kept.
func extractCycloneDXPackages(c *gabs.Container) []data.PackageLicense {
	children := c.Search("components").Children()
	out := make([]data.PackageLicense, 0, len(children))
	for _, comp := range children {
		if str(comp, "type") == "file" {
			continue
		}
		name := str(comp, "name")
		if name == "" {
			continue
		}
		pkg := data.PackageLicense{
			Package:  name,
			Version:  str(comp, "version"),
			PURL:     str(comp, "purl"),
			Licenses: cyclonedxLicenses(comp),
		}
		out = append(out, pkg)
		if len(out) >= maxPackages {
			break
		}
	}
	return out
}

// cyclonedxLicenses extracts the license identifiers from a component's
// licenses[] array, deduped and order-preserved.
func cyclonedxLicenses(comp *gabs.Container) []string {
	var lics []string
	seen := map[string]struct{}{}
	add := func(s string) {
		s = trimLicense(s)
		if s == "" {
			return
		}
		if _, dup := seen[s]; dup {
			return
		}
		seen[s] = struct{}{}
		lics = append(lics, s)
	}
	for _, l := range comp.Search("licenses").Children() {
		// {license:{id}} | {license:{name}} | {expression}
		if id := str(l, "license", "id"); id != "" {
			add(id)
			continue
		}
		if nm := str(l, "license", "name"); nm != "" {
			add(nm)
			continue
		}
		if ex := str(l, "expression"); ex != "" {
			add(ex)
		}
	}
	return lics
}

// extractSPDXPackages reads packages[].{name,versionInfo,licenseDeclared||
// licenseConcluded||licenseInfoFromFiles[]}. The root image/document package is
// skipped — it describes the subject, not a dependency. License selection
// prefers declared, then concluded, then per-file info, keeping every distinct
// non-placeholder value (NOASSERTION/NONE are dropped so they don't drown real
// data; a package left with zero licenses is correctly classified "unknown").
func extractSPDXPackages(c *gabs.Container) []data.PackageLicense {
	children := c.Search("packages").Children()
	out := make([]data.PackageLicense, 0, len(children))
	for _, p := range children {
		id := str(p, "SPDXID")
		if isSPDXRootImage(id) {
			continue
		}
		name := str(p, "name")
		if name == "" {
			continue
		}
		pkg := data.PackageLicense{
			Package:  name,
			Version:  str(p, "versionInfo"),
			PURL:     spdxPURL(p),
			Licenses: spdxLicenses(p),
		}
		out = append(out, pkg)
		if len(out) >= maxPackages {
			break
		}
	}
	return out
}

// spdxLicenses picks the best-available license field and returns its distinct
// non-placeholder values. Expressions ("A AND B") are kept intact — the data
// package parses/evaluates them.
func spdxLicenses(p *gabs.Container) []string {
	if v := trimLicense(str(p, "licenseDeclared")); v != "" && !isPlaceholderLicense(v) {
		return []string{v}
	}
	if v := trimLicense(str(p, "licenseConcluded")); v != "" && !isPlaceholderLicense(v) {
		return []string{v}
	}
	var lics []string
	seen := map[string]struct{}{}
	for _, f := range p.Search("licenseInfoFromFiles").Children() {
		s, _ := f.Data().(string)
		v := strings.TrimSpace(s)
		if v == "" || isPlaceholderLicense(v) {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		lics = append(lics, v)
	}
	return lics
}

// spdxPURL returns the package's PURL from externalRefs, if present.
func spdxPURL(p *gabs.Container) string {
	for _, ref := range p.Search("externalRefs").Children() {
		if str(ref, "referenceType") == "purl" {
			return str(ref, "referenceLocator")
		}
	}
	return ""
}

// isSPDXRootImage reports whether an SPDXID identifies the subject image/document
// root rather than a catalogued dependency (mirrors the resolveSPDX heuristic).
func isSPDXRootImage(id string) bool {
	return strings.Contains(id, "DocumentRoot-Image") || strings.Contains(id, "ContainerImage")
}

// isPlaceholderLicense reports whether v is an SPDX "no data" sentinel.
func isPlaceholderLicense(v string) bool {
	return v == "NOASSERTION" || v == "NONE"
}

func trimLicense(s string) string { return strings.TrimSpace(s) }

package data

import (
	"slices"
	"sort"
	"strings"
)

// LicenseCategory buckets a license by the obligation class that matters for
// compliance policy. It is deliberately coarse — the axis a policy reasons about
// is "how strong is the copyleft", not the exact license.
type LicenseCategory string

const (
	// CategoryPermissive: attribution-only licenses (MIT, BSD, Apache, ISC, …).
	CategoryPermissive LicenseCategory = "permissive"
	// CategoryWeakCopyleft: file/library-scope copyleft (LGPL, MPL, EPL, …).
	CategoryWeakCopyleft LicenseCategory = "weak-copyleft"
	// CategoryStrongCopyleft: project-scope copyleft (GPL, AGPL, …).
	CategoryStrongCopyleft LicenseCategory = "strong-copyleft"
	// CategoryProprietary: commercial / non-OSS / source-unavailable licenses.
	CategoryProprietary LicenseCategory = "proprietary"
	// CategoryUnknown: unresolvable, absent, or unrecognized (NOASSERTION,
	// LicenseRef-*, empty). Fail-visible — never silently treated as permissive.
	CategoryUnknown LicenseCategory = "unknown"
)

// ValidLicenseCategories is the ordered set a policy may deny. Ordered most→least
// permissive for stable display.
var ValidLicenseCategories = []LicenseCategory{
	CategoryPermissive, CategoryWeakCopyleft, CategoryStrongCopyleft,
	CategoryProprietary, CategoryUnknown,
}

// ValidLicenseCategory reports whether s names a known category.
func ValidLicenseCategory(s string) bool {
	return slices.Contains(ValidLicenseCategories, LicenseCategory(s))
}

// PackageLicense is one catalogued component's license inventory, extracted from
// the SBOM at ingest. It is scanner-agnostic and format-agnostic: the CycloneDX
// and SPDX walkers both normalize into this shape. The full license set is
// preserved (never collapsed to a single "winner") so multi-license packages and
// SPDX expressions can be evaluated faithfully downstream.
type PackageLicense struct {
	// Package is the component name.
	Package string `json:"package"`
	// Version is the component version ("" if the SBOM omitted it).
	Version string `json:"version"`
	// PURL is the package URL, when the SBOM carried one.
	PURL string `json:"purl,omitempty"`
	// Licenses is the set of license IDs / expressions as stated by the SBOM,
	// normalized (trimmed, de-duped) but NOT canonicalized to SPDX IDs — the raw
	// values are authoritative and classification happens at read time.
	Licenses []string `json:"licenses"`
}

// licenseTaxonomyVersion identifies the classification map below. Bumped whenever
// the map changes so a classification can be tied to a known taxonomy revision.
const licenseTaxonomyVersion = "1"

// LicenseTaxonomyVersion returns the current taxonomy revision.
func LicenseTaxonomyVersion() string { return licenseTaxonomyVersion }

// exactLicenseCategory maps normalized (see normalizeLicenseID) SPDX IDs to a
// category. Not exhaustive — the SPDX list has hundreds of entries — but covers
// the licenses that actually appear in container SBOMs. Unmatched IDs fall
// through to prefix rules, then to CategoryUnknown.
var exactLicenseCategory = map[string]LicenseCategory{
	// permissive
	"mit":          CategoryPermissive,
	"mit-0":        CategoryPermissive,
	"isc":          CategoryPermissive,
	"apache-2.0":   CategoryPermissive,
	"apache-1.1":   CategoryPermissive,
	"bsd-2-clause": CategoryPermissive,
	"bsd-3-clause": CategoryPermissive,
	"bsd-4-clause": CategoryPermissive,
	"0bsd":         CategoryPermissive,
	"zlib":         CategoryPermissive,
	"libpng":       CategoryPermissive,
	"png-2.0":      CategoryPermissive,
	"x11":          CategoryPermissive,
	"unlicense":    CategoryPermissive,
	"wtfpl":        CategoryPermissive,
	"python-2.0":   CategoryPermissive,
	"psf-2.0":      CategoryPermissive,
	"postgresql":   CategoryPermissive,
	"ncsa":         CategoryPermissive,
	"boost-1.0":    CategoryPermissive,
	"bsl-1.0":      CategoryPermissive,
	"cc0-1.0":      CategoryPermissive,
	"cc-by-4.0":    CategoryPermissive,
	"cc-by-3.0":    CategoryPermissive,

	// weak copyleft (file/library scope)
	"lgpl-2.0":     CategoryWeakCopyleft,
	"lgpl-2.1":     CategoryWeakCopyleft,
	"lgpl-3.0":     CategoryWeakCopyleft,
	"mpl-1.1":      CategoryWeakCopyleft,
	"mpl-2.0":      CategoryWeakCopyleft,
	"epl-1.0":      CategoryWeakCopyleft,
	"epl-2.0":      CategoryWeakCopyleft,
	"cddl-1.0":     CategoryWeakCopyleft,
	"cddl-1.1":     CategoryWeakCopyleft,
	"cpl-1.0":      CategoryWeakCopyleft,
	"ms-pl":        CategoryWeakCopyleft,
	"artistic-2.0": CategoryWeakCopyleft,

	// strong copyleft (project scope)
	"gpl-1.0":   CategoryStrongCopyleft,
	"gpl-2.0":   CategoryStrongCopyleft,
	"gpl-3.0":   CategoryStrongCopyleft,
	"agpl-1.0":  CategoryStrongCopyleft,
	"agpl-3.0":  CategoryStrongCopyleft,
	"sleepycat": CategoryStrongCopyleft,

	// proprietary / non-OSS
	"proprietary":  CategoryProprietary,
	"commercial":   CategoryProprietary,
	"ms-eula":      CategoryProprietary,
	"cc-by-nc-4.0": CategoryProprietary,
	"cc-by-nd-4.0": CategoryProprietary,
}

// normalizeLicenseID lowercases, trims, and strips SPDX modifier suffixes so
// "GPL-3.0-only", "GPL-3.0-or-later", and "GPL-3.0+" all resolve to "gpl-3.0".
// It does NOT alter the stored value — only the key used for classification.
func normalizeLicenseID(id string) string {
	s := strings.ToLower(strings.TrimSpace(id))
	s = strings.TrimSuffix(s, "+")
	for _, suf := range []string{"-only", "-or-later"} {
		s = strings.TrimSuffix(s, suf)
	}
	return s
}

// Classify maps a single license ID to a category. An empty value, NOASSERTION,
// NONE, or a LicenseRef-* placeholder is CategoryUnknown. Unrecognized IDs are
// also CategoryUnknown (fail-visible), except where a family prefix is
// unambiguous (e.g. any "agpl-*" is strong copyleft).
func Classify(id string) LicenseCategory {
	n := normalizeLicenseID(id)
	if n == "" || n == "noassertion" || n == "none" || strings.HasPrefix(n, "licenseref") {
		return CategoryUnknown
	}
	if c, ok := exactLicenseCategory[n]; ok {
		return c
	}
	// Family prefixes for versions not enumerated above. Order matters: agpl and
	// lgpl must be tested before the bare "gpl" prefix.
	switch {
	case strings.HasPrefix(n, "agpl"):
		return CategoryStrongCopyleft
	case strings.HasPrefix(n, "lgpl"):
		return CategoryWeakCopyleft
	case strings.HasPrefix(n, "gpl"):
		return CategoryStrongCopyleft
	case strings.HasPrefix(n, "mpl"), strings.HasPrefix(n, "epl"), strings.HasPrefix(n, "cddl"):
		return CategoryWeakCopyleft
	case strings.HasPrefix(n, "bsd"), strings.HasPrefix(n, "apache"),
		strings.HasPrefix(n, "mit"), strings.HasPrefix(n, "cc-by-") && !strings.Contains(n, "-nc") && !strings.Contains(n, "-nd"):
		return CategoryPermissive
	}
	return CategoryUnknown
}

// LicenseFamily returns a short, display-friendly grouping key for a license ID
// — the prefix before the first version number / dash-number. Used to bucket the
// distribution donut and treemap (e.g. "GPL-2.0", "GPL-3.0" → "GPL"). Unlike
// disco's fragile SQL string-splitting, this operates on the individual ID after
// expression parsing, not on a whole expression string.
func LicenseFamily(id string) string {
	n := strings.TrimSpace(id)
	if n == "" {
		return "unknown"
	}
	if strings.EqualFold(n, "noassertion") || strings.EqualFold(n, "none") {
		return "unknown"
	}
	if i := strings.IndexAny(n, "-"); i > 0 {
		// keep the alpha family prefix (BSD-3-Clause → BSD, GPL-2.0 → GPL).
		head := n[:i]
		return strings.ToUpper(head)
	}
	return n
}

// ── SPDX license expression parsing / evaluation ────────────────────────────────

// exprTokens is the set of SPDX expression operators/keywords, lowercased.
var exprOperators = map[string]bool{"and": true, "or": true, "with": true}

// ParseExpression extracts the distinct license IDs referenced by an SPDX license
// expression such as "MIT OR Apache-2.0", "(MIT AND BSD-3-Clause)", or
// "GPL-2.0-only WITH Classpath-exception-2.0". Operators, parentheses, and the
// exception operand following WITH are dropped; only the license IDs remain. It
// is a tokenizer, not a full boolean parser — see EvaluateExpression for the
// (documented) precedence simplification.
func ParseExpression(expr string) []string {
	fields := strings.FieldsFunc(expr, func(r rune) bool {
		return r == '(' || r == ')' || r == ' ' || r == '\t' || r == '\n'
	})
	var out []string
	seen := map[string]struct{}{}
	skipNext := false
	for _, f := range fields {
		low := strings.ToLower(f)
		if low == "with" {
			// The operand after WITH is a license exception, not a license.
			skipNext = true
			continue
		}
		if skipNext {
			skipNext = false
			continue
		}
		if exprOperators[low] {
			continue
		}
		if _, dup := seen[low]; dup {
			continue
		}
		seen[low] = struct{}{}
		out = append(out, f)
	}
	return out
}

// isSimpleExpr reports whether expr is a single license ID (no operators).
func isSimpleExpr(expr string) bool {
	for f := range strings.FieldsSeq(expr) {
		if exprOperators[strings.ToLower(f)] {
			return false
		}
	}
	return !strings.ContainsAny(expr, "()")
}

// EvaluateExpression decides whether a license expression is allowed given a set
// of denied license IDs (already lowercased/normalized keys — see the policy
// evaluator). Semantics:
//
//   - OR  → allowed if ANY operand is allowed (the licensee may choose).
//   - AND → allowed only if ALL operands are allowed.
//
// Precedence simplification (documented): a mixed AND/OR expression is treated as
// disjunctive-normal-friendly only at the top level — nested parentheses are
// flattened, so "(A AND B) OR C" is evaluated as "at least one of {A,B,C}
// allowed" rather than strict boolean algebra. This is intentionally permissive
// (favors the licensee) and covers the expressions seen in real SBOMs; a full
// parser is a documented later upgrade. Returns the allowing/violating decision
// and, on violation, the specific denied IDs.
func EvaluateExpression(expr string, denied map[string]struct{}) (allowed bool, offending []string) {
	ids := ParseExpression(expr)
	if len(ids) == 0 {
		// No resolvable license → treat as not-allowed only if "unknown"-style is
		// denied; the caller (Evaluate) handles unknown via category, so here an
		// empty parse is vacuously allowed.
		return true, nil
	}

	hasOR := false
	for f := range strings.FieldsSeq(expr) {
		if strings.EqualFold(f, "or") {
			hasOR = true
			break
		}
	}

	var deniedIDs []string
	for _, id := range ids {
		if _, bad := denied[normalizeLicenseID(id)]; bad {
			deniedIDs = append(deniedIDs, id)
		}
	}

	if hasOR {
		// Allowed if at least one operand is not denied.
		allowedCount := len(ids) - len(deniedIDs)
		if allowedCount > 0 {
			return true, nil
		}
		return false, deniedIDs
	}
	// Pure AND (or a single ID): any denied operand violates.
	if len(deniedIDs) > 0 {
		return false, deniedIDs
	}
	return true, nil
}

// LicensePolicy is a tenant's opt-in compliance policy. An empty policy denies
// nothing (DevRadar is descriptive by default; enforcement is opt-in).
type LicensePolicy struct {
	// DeniedCategories are license categories that fail the policy.
	DeniedCategories []LicenseCategory `json:"denied_categories"`
	// AllowExceptions are license IDs permitted even if their category is denied
	// (e.g. deny strong-copyleft but allow one specifically-approved GPL library).
	AllowExceptions []string `json:"allow_exceptions"`
	// DenyExceptions are license IDs always flagged regardless of category.
	DenyExceptions []string `json:"deny_exceptions"`
}

// IsEmpty reports whether the policy denies nothing.
func (p LicensePolicy) IsEmpty() bool {
	return len(p.DeniedCategories) == 0 && len(p.DenyExceptions) == 0
}

// deniedLicenseSet builds the set of normalized license IDs the policy forbids:
// every ID whose category is denied (minus allow-exceptions), plus every
// deny-exception ID. Returned keyed by normalizeLicenseID for matching.
func (p LicensePolicy) deniedLicenseSet(candidateIDs []string) map[string]struct{} {
	deniedCat := map[LicenseCategory]struct{}{}
	for _, c := range p.DeniedCategories {
		deniedCat[c] = struct{}{}
	}
	allowEx := map[string]struct{}{}
	for _, id := range p.AllowExceptions {
		allowEx[normalizeLicenseID(id)] = struct{}{}
	}
	denied := map[string]struct{}{}
	for _, id := range candidateIDs {
		n := normalizeLicenseID(id)
		if _, ok := deniedCat[Classify(id)]; ok {
			if _, allowed := allowEx[n]; !allowed {
				denied[n] = struct{}{}
			}
		}
	}
	for _, id := range p.DenyExceptions {
		denied[normalizeLicenseID(id)] = struct{}{}
	}
	return denied
}

// Evaluate reports whether a package violates the policy and, if so, a
// human-readable reason.
//
// A package's license entries are a CONJUNCTION: the package is bound by every
// entry, so it violates if ANY entry is a violation. This matches how the two
// SBOM formats represent the same package — CycloneDX lists each applicable
// license as a separate entry (e.g. apt → BSD-3-Clause, GPL-2.0, curl, …) while
// SPDX joins them with AND ("BSD-3-Clause AND GPL-2.0-only AND …"). Treating
// multiple entries as a choice (OR) would wrongly clear a package that ships
// permissive AND copyleft code. Choice is expressed only WITHIN a single entry
// via an SPDX "OR" expression, which EvaluateExpression relaxes correctly.
//
// A package with no licenses is a violation only when the policy denies the
// "unknown" category.
func (p LicensePolicy) Evaluate(pkg PackageLicense) (violation bool, reason string) {
	if p.IsEmpty() {
		return false, ""
	}

	deniesUnknown := slices.Contains(p.DeniedCategories, CategoryUnknown)

	if len(pkg.Licenses) == 0 {
		if deniesUnknown {
			return true, "no license declared (unknown)"
		}
		return false, ""
	}

	// Collect every candidate ID across all entries so the denied set is complete.
	var allIDs []string
	for _, entry := range pkg.Licenses {
		allIDs = append(allIDs, ParseExpression(entry)...)
	}
	denied := p.deniedLicenseSet(allIDs)

	var offending []string
	for _, entry := range pkg.Licenses {
		if isSimpleExpr(entry) {
			if _, bad := denied[normalizeLicenseID(entry)]; bad {
				offending = append(offending, entry)
			}
			continue
		}
		// A compound expression: OR relaxes, AND is strict (see EvaluateExpression).
		if ok, off := EvaluateExpression(entry, denied); !ok {
			offending = append(offending, off...)
		}
	}

	if len(offending) == 0 {
		return false, ""
	}
	return true, "denied license: " + strings.Join(dedupeSorted(offending), ", ")
}

func dedupeSorted(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

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
const licenseTaxonomyVersion = "2"

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
	"cc0":          CategoryPermissive,
	"cc-by-4.0":    CategoryPermissive,
	"cc-by-3.0":    CategoryPermissive,

	// permissive — additional licenses observed in container SBOMs (Debian/OS
	// base-image copyright shorthands and less-common SPDX IDs). Whole families
	// (expat/*, public-domain/*, permissive/*, fsf/*) are covered by prefix rules
	// in Classify; these are the one-off IDs.
	"beerware":           CategoryPermissive, // "buy me a beer" — permissive
	"kazlib":             CategoryPermissive, // BSD-style
	"gap":                CategoryPermissive,
	"unicode":            CategoryPermissive,
	"unicode-dfs-2016":   CategoryPermissive,
	"latex2e":            CategoryPermissive,
	"freesoftware":       CategoryPermissive,
	"pcre":               CategoryPermissive, // BSD-style
	"bzip":               CategoryPermissive, // bzip2 license — BSD-style
	"tcl-like":           CategoryPermissive,
	"tinyscheme":         CategoryPermissive, // BSD-style
	"autoconf":           CategoryPermissive, // all-permissive with exception
	"isc+ibm":            CategoryPermissive,
	"isc-original":       CategoryPermissive,
	"curl":               CategoryPermissive, // MIT-style
	"hpnd":               CategoryPermissive, // Historical Permission Notice
	"hpnd-sell-variant":  CategoryPermissive,
	"openldap":           CategoryPermissive,
	"oldap-2.8":          CategoryPermissive,
	"openldap-2.8":       CategoryPermissive,
	"ftl":                CategoryPermissive, // FreeType License
	"ntp":                CategoryPermissive,
	"opengroup-mit":      CategoryPermissive,
	"carnegie":           CategoryPermissive, // CMU/BSD-style
	"bitstream-vera":     CategoryPermissive,
	"sunpro":             CategoryPermissive,
	"dec":                CategoryPermissive,
	"rsa-md":             CategoryPermissive, // RSA message-digest notice
	"pd":                 CategoryPermissive, // public-domain shorthand
	"pd-debian":          CategoryPermissive,
	"sdbm-public-domain": CategoryPermissive,

	// weak copyleft (file/library scope)
	"lgpl-2.0":      CategoryWeakCopyleft,
	"lgpl-2.1":      CategoryWeakCopyleft,
	"lgpl-3.0":      CategoryWeakCopyleft,
	"mpl-1.1":       CategoryWeakCopyleft,
	"mpl-2.0":       CategoryWeakCopyleft,
	"epl-1.0":       CategoryWeakCopyleft,
	"epl-2.0":       CategoryWeakCopyleft,
	"cddl-1.0":      CategoryWeakCopyleft,
	"cddl-1.1":      CategoryWeakCopyleft,
	"cpl-1.0":       CategoryWeakCopyleft,
	"ms-pl":         CategoryWeakCopyleft,
	"artistic-2.0":  CategoryWeakCopyleft,
	"artistic":      CategoryWeakCopyleft, // Artistic v1 — treated as weak copyleft
	"artistic-1.0":  CategoryWeakCopyleft,
	"artistic-dist": CategoryWeakCopyleft,

	// strong copyleft (project scope). GNU Free Documentation License (gfdl/*, and
	// the fdl- alias) is documentation copyleft — classified weak-copyleft via the
	// prefix rules in Classify, not here.
	"gpl-1.0":             CategoryStrongCopyleft,
	"gpl-2.0":             CategoryStrongCopyleft,
	"gpl-3.0":             CategoryStrongCopyleft,
	"agpl-1.0":            CategoryStrongCopyleft,
	"agpl-3.0":            CategoryStrongCopyleft,
	"sleepycat":           CategoryStrongCopyleft,
	"dont-change-the-gpl": CategoryStrongCopyleft, // Debian shorthand for a GPL notice
	"smail-gpl":           CategoryStrongCopyleft,

	// proprietary / non-OSS
	"proprietary":  CategoryProprietary,
	"commercial":   CategoryProprietary,
	"ms-eula":      CategoryProprietary,
	"cc-by-nc-4.0": CategoryProprietary,
	"cc-by-nd-4.0": CategoryProprietary,
	"noderivs":     CategoryProprietary, // no-derivatives — fails typical OSS policy
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
	// A digest leaked into the license field (SBOM-generator bug, not a license).
	// Unknown, like the cases above — but see IsMalformedLicense, which callers
	// use to report these separately from genuinely unrecognized licenses.
	if isDigestValue(n) {
		return CategoryUnknown
	}
	if c, ok := exactLicenseCategory[n]; ok {
		return c
	}
	// Family prefixes for variants not enumerated above. Order matters: agpl and
	// lgpl must be tested before the bare "gpl" prefix; gfdl/fdl (documentation
	// copyleft) before nothing GPL-ish since they don't start with "gpl".
	switch {
	case strings.HasPrefix(n, "agpl"):
		return CategoryStrongCopyleft
	case strings.HasPrefix(n, "lgpl"):
		return CategoryWeakCopyleft
	case strings.HasPrefix(n, "gfdl"), strings.HasPrefix(n, "fdl"):
		return CategoryWeakCopyleft // GNU Free Documentation License (docs copyleft)
	case strings.HasPrefix(n, "gpl"):
		return CategoryStrongCopyleft
	case strings.HasPrefix(n, "mpl"), strings.HasPrefix(n, "epl"), strings.HasPrefix(n, "cddl"):
		return CategoryWeakCopyleft
	case strings.HasPrefix(n, "bsd"), strings.HasPrefix(n, "apache"),
		strings.HasPrefix(n, "mit"),
		strings.HasPrefix(n, "expat"), // Expat IS the MIT license
		strings.HasPrefix(n, "public-domain"), n == "public.domain",
		strings.HasPrefix(n, "permissive"), // permissive, permissive-fsf, permissive-nowarranty, …
		strings.HasPrefix(n, "fsful"), strings.HasPrefix(n, "fsfap"), strings.HasPrefix(n, "fsf-"),
		strings.HasPrefix(n, "hpnd"),
		strings.HasPrefix(n, "cc-by-") && !strings.Contains(n, "-nc") && !strings.Contains(n, "-nd"):
		return CategoryPermissive
	}
	return CategoryUnknown
}

// isDigestValue reports whether a normalized license value is actually a content
// digest (sha256:…/sha512:…) that a buggy SBOM generator wrote into the license
// field. These are not licenses.
func isDigestValue(n string) bool {
	return strings.HasPrefix(n, "sha256:") || strings.HasPrefix(n, "sha512:") ||
		strings.HasPrefix(n, "sha1:") || strings.HasPrefix(n, "md5:")
}

// IsMalformedLicense reports whether a raw license value is structurally not a
// license (a leaked content digest). Callers can surface these separately from
// merely unrecognized licenses — both classify as CategoryUnknown, but the cause
// (and the fix: report the SBOM-generator bug) differs.
func IsMalformedLicense(id string) bool {
	return isDigestValue(normalizeLicenseID(id))
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
	// A content digest (sha256:…) leaked into the license field by a buggy SBOM
	// generator — not a license, and not something we can walk up to a real one.
	// Fold it into "unknown" so it never appears as its own family in the treemap
	// or legend. Matches Classify's digest handling (see isDigestValue).
	if isDigestValue(normalizeLicenseID(n)) {
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

// EvaluateExpression decides whether a license expression is allowed given a set
// of denied license IDs (already lowercased/normalized keys — see the policy
// evaluator). It parses the SPDX expression into a boolean AST and evaluates it
// with correct precedence:
//
//   - OR   → allowed if ANY operand is allowed (the licensee may choose).
//   - AND  → allowed only if ALL operands are allowed.
//   - WITH → binds a license to an exception as a single leaf.
//   - parentheses group as written.
//
// So "(MIT OR GPL-3.0) AND Proprietary" is correctly DENIED when Proprietary is
// denied — the mandatory AND-ed operand is not masked by the OR (the bug in the
// prior flatten-and-scan heuristic). Returns the decision and, on violation, the
// specific denied IDs. An expression with no resolvable license is vacuously
// allowed here (the caller handles the unknown category separately).
func EvaluateExpression(expr string, denied map[string]struct{}) (allowed bool, offending []string) {
	root := parseLicenseExpression(expr)
	if root == nil {
		return true, nil
	}
	// Predicate over the flat denied set: a leaf is denied if its bare license key
	// is denied OR (when it carries an exception) its "license WITH exception" pair
	// key is denied. This preserves the historical flat-set contract for callers
	// that pass a precomputed set; the policy-aware path (LicensePolicy.Evaluate)
	// uses deniedLeafForPolicy instead, which can ALLOW a pair whose bare license is
	// denied.
	isDenied := func(license, excep string) (bool, string) {
		if excep != "" {
			pair := normalizeLicenseID(license) + " with " + strings.ToLower(strings.TrimSpace(excep))
			if _, bad := denied[pair]; bad {
				return true, license + " WITH " + excep
			}
		}
		if _, bad := denied[normalizeLicenseID(license)]; bad {
			return true, license
		}
		return false, ""
	}
	var off []string
	if root.eval(isDenied, &off) {
		return true, nil
	}
	return false, off
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

	var offending []string
	for _, entry := range pkg.Licenses {
		// Parse each entry as its own SPDX expression. A MALFORMED entry (missing
		// operand, unbalanced parens, trailing junk) must NOT be turned into a
		// partial verdict — the tolerant parser could otherwise read "MIT OR" as an
		// allowed MIT, or "(GPL-3.0" as a denied GPL. Treat it as UNKNOWN instead:
		// a data-quality signal the tenant's existing unknown-category policy
		// decides (denied ⇒ violation, otherwise descriptive only).
		root, malformed := parseLicenseExpressionChecked(entry)
		if malformed || root == nil {
			if deniesUnknown {
				offending = append(offending, entry+" (unparseable)")
			}
			continue
		}
		var off []string
		if !root.eval(p.deniedLeafForPolicy(), &off) {
			offending = append(offending, off...)
		}
	}

	if len(offending) == 0 {
		return false, ""
	}
	return true, "denied license: " + strings.Join(dedupeSorted(offending), ", ")
}

// deniedLeafForPolicy returns a per-leaf predicate that honors WITH exceptions at
// pair granularity. A leaf is denied when its category is denied (or it is a
// DenyException) UNLESS an allow-exception clears it — and an allow-exception may
// be either the bare license ("gpl-2.0") or the specific pair
// ("gpl-2.0 with classpath-exception-2.0"). This is what lets a policy deny a
// whole category but permit one license only WHEN accompanied by its exception,
// as documented — the flat denied-set path could not express that.
func (p LicensePolicy) deniedLeafForPolicy() deniedLeaf {
	deniedCat := map[LicenseCategory]struct{}{}
	for _, c := range p.DeniedCategories {
		deniedCat[c] = struct{}{}
	}
	allowEx := map[string]struct{}{}
	for _, id := range p.AllowExceptions {
		allowEx[normalizeLicenseID(id)] = struct{}{}
		allowEx[normalizeExceptionKey(id)] = struct{}{} // also allow a raw pair form
	}
	denyEx := map[string]struct{}{}
	for _, id := range p.DenyExceptions {
		denyEx[normalizeLicenseID(id)] = struct{}{}
		denyEx[normalizeExceptionKey(id)] = struct{}{}
	}

	return func(license, excep string) (bool, string) {
		bare := normalizeLicenseID(license)
		display := license
		pair := bare
		if excep != "" {
			pair = bare + " with " + strings.ToLower(strings.TrimSpace(excep))
			display = license + " WITH " + excep
		}

		// A pair-specific or bare allow-exception clears the leaf entirely.
		if _, ok := allowEx[pair]; ok {
			return false, ""
		}
		if excep != "" {
			if _, ok := allowEx[bare]; ok {
				return false, ""
			}
		}
		// Explicit deny-exception (pair or bare) always flags.
		if _, ok := denyEx[pair]; ok {
			return true, display
		}
		if _, ok := denyEx[bare]; ok {
			return true, display
		}
		// Otherwise category-driven.
		if _, ok := deniedCat[Classify(license)]; ok {
			return true, display
		}
		return false, ""
	}
}

// normalizeExceptionKey lowercases/trims an "id WITH exception" string to the
// space-joined form used as a pair key, or returns the plain normalized id when
// there is no WITH.
func normalizeExceptionKey(id string) string {
	low := strings.ToLower(strings.TrimSpace(id))
	if lic, exc, found := strings.Cut(low, " with "); found {
		return normalizeLicenseID(lic) + " with " + strings.TrimSpace(exc)
	}
	return normalizeLicenseID(id)
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

package data

import (
	"reflect"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := map[string]LicenseCategory{
		"MIT":                       CategoryPermissive,
		"Apache-2.0":                CategoryPermissive,
		"BSD-3-Clause":              CategoryPermissive,
		"ISC":                       CategoryPermissive,
		"Zlib":                      CategoryPermissive,
		"LGPL-2.1":                  CategoryWeakCopyleft,
		"LGPL-3.0-only":             CategoryWeakCopyleft,
		"MPL-2.0":                   CategoryWeakCopyleft,
		"EPL-2.0":                   CategoryWeakCopyleft,
		"GPL-2.0":                   CategoryStrongCopyleft,
		"GPL-3.0-or-later":          CategoryStrongCopyleft,
		"GPL-3.0+":                  CategoryStrongCopyleft,
		"AGPL-3.0":                  CategoryStrongCopyleft,
		"proprietary":               CategoryProprietary,
		"commercial":                CategoryProprietary,
		"NOASSERTION":               CategoryUnknown,
		"NONE":                      CategoryUnknown,
		"":                          CategoryUnknown,
		"LicenseRef-scancode-xyz":   CategoryUnknown,
		"totally-made-up-license-9": CategoryUnknown,

		// Taxonomy v2 additions (licenses observed in real container SBOMs).
		"Expat":               CategoryPermissive, // synonym for MIT
		"expat":               CategoryPermissive, // case-insensitive
		"public-domain":       CategoryPermissive, // family prefix
		"public-domain-md5":   CategoryPermissive, // family prefix variant
		"PD":                  CategoryPermissive, // Debian shorthand
		"CC0":                 CategoryPermissive, // no-version alias
		"Beerware":            CategoryPermissive,
		"Unicode":             CategoryPermissive,
		"permissive":          CategoryPermissive, // family prefix
		"permissive-fsf":      CategoryPermissive, // family prefix variant
		"FSFAP":               CategoryPermissive, // fsf prefix
		"FSFULLR":             CategoryPermissive, // fsful prefix
		"HPND":                CategoryPermissive,
		"GFDL-1.3-only":       CategoryWeakCopyleft, // documentation copyleft (gfdl prefix)
		"GFDL-NIV-1.3":        CategoryWeakCopyleft,
		"FDL-1.2+":            CategoryWeakCopyleft, // fdl alias
		"Artistic":            CategoryWeakCopyleft, // Artistic v1
		"noderivs":            CategoryProprietary,  // no-derivatives
		"SMAIL-GPL":           CategoryStrongCopyleft,
		"DONT-CHANGE-THE-GPL": CategoryStrongCopyleft,
		// A digest leaked into the license field is unknown (not a license).
		"sha256:da8191658b3452ce9caf31638ba61dab31a38c619fa39df119812e050f592fd3": CategoryUnknown,
	}
	for in, want := range cases {
		if got := Classify(in); got != want {
			t.Errorf("Classify(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestIsMalformedLicense distinguishes a leaked content digest (an SBOM-generator
// bug) from a merely unrecognized license — both are CategoryUnknown, but only
// the digest is "malformed".
func TestIsMalformedLicense(t *testing.T) {
	malformed := []string{
		"sha256:da8191658b3452ce9caf31638ba61dab31a38c619fa39df119812e050f592fd3",
		"SHA512:abcdef",
		"md5:0123456789abcdef",
	}
	for _, id := range malformed {
		if !IsMalformedLicense(id) {
			t.Errorf("IsMalformedLicense(%q) = false, want true", id)
		}
	}
	notMalformed := []string{"MIT", "NOASSERTION", "totally-unknown-thing", ""}
	for _, id := range notMalformed {
		if IsMalformedLicense(id) {
			t.Errorf("IsMalformedLicense(%q) = true, want false", id)
		}
	}
}

func TestClassifyFamilyPrefixOrdering(t *testing.T) {
	// AGPL/LGPL must not be swallowed by the bare "gpl" prefix rule.
	if got := Classify("AGPL-4.0"); got != CategoryStrongCopyleft {
		t.Errorf("AGPL-4.0 = %q, want strong-copyleft", got)
	}
	if got := Classify("LGPL-4.0"); got != CategoryWeakCopyleft {
		t.Errorf("LGPL-4.0 = %q, want weak-copyleft", got)
	}
	if got := Classify("GPL-4.0"); got != CategoryStrongCopyleft {
		t.Errorf("GPL-4.0 = %q, want strong-copyleft", got)
	}
}

func TestLicenseFamily(t *testing.T) {
	cases := map[string]string{
		"GPL-2.0":      "GPL",
		"GPL-3.0":      "GPL",
		"BSD-3-Clause": "BSD",
		"Apache-2.0":   "APACHE",
		"MIT":          "MIT",
		"NOASSERTION":  "unknown",
		"":             "unknown",
		// A leaked content digest is not a license family — folds into unknown.
		"sha256:da8191658b3452ce9caf31638ba61dab31a38c619fa39df119812e050f592fd3": "unknown",
	}
	for in, want := range cases {
		if got := LicenseFamily(in); got != want {
			t.Errorf("LicenseFamily(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseExpression(t *testing.T) {
	cases := []struct {
		expr string
		want []string
	}{
		{"MIT", []string{"MIT"}},
		{"MIT OR Apache-2.0", []string{"MIT", "Apache-2.0"}},
		{"(MIT AND BSD-3-Clause)", []string{"MIT", "BSD-3-Clause"}},
		{"GPL-2.0-only WITH Classpath-exception-2.0", []string{"GPL-2.0-only"}},
		{"MIT OR MIT", []string{"MIT"}}, // dedup
		{"", nil},
	}
	for _, c := range cases {
		if got := ParseExpression(c.expr); !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParseExpression(%q) = %v, want %v", c.expr, got, c.want)
		}
	}
}

func TestEvaluateExpression(t *testing.T) {
	denied := map[string]struct{}{"gpl-3.0": {}, "gpl-2.0": {}}

	// OR: allowed because MIT is an allowed operand.
	if ok, _ := EvaluateExpression("MIT OR GPL-3.0", denied); !ok {
		t.Error("MIT OR GPL-3.0 should be allowed (OR relaxation)")
	}
	// OR: all operands denied → violation.
	if ok, off := EvaluateExpression("GPL-2.0 OR GPL-3.0", denied); ok || len(off) != 2 {
		t.Errorf("GPL-2.0 OR GPL-3.0 should violate with 2 offenders, got ok=%v off=%v", ok, off)
	}
	// AND: any denied operand violates.
	if ok, off := EvaluateExpression("MIT AND GPL-3.0", denied); ok || len(off) != 1 {
		t.Errorf("MIT AND GPL-3.0 should violate with 1 offender, got ok=%v off=%v", ok, off)
	}
	// AND: all allowed → allowed.
	if ok, _ := EvaluateExpression("MIT AND Apache-2.0", denied); !ok {
		t.Error("MIT AND Apache-2.0 should be allowed")
	}
	// WITH operand is an exception, not a license — GPL-3.0 still denied.
	if ok, _ := EvaluateExpression("GPL-3.0-only WITH Classpath-exception-2.0", denied); ok {
		t.Error("GPL-3.0 WITH exception should still violate (GPL-3.0 denied)")
	}

	// MIXED precedence — the case the old flatten-and-scan heuristic got WRONG.
	// A mandatory (AND-ed) denied operand must NOT be masked by an OR elsewhere.
	if ok, off := EvaluateExpression("(MIT OR Apache-2.0) AND GPL-3.0", denied); ok || len(off) != 1 {
		t.Errorf("(MIT OR Apache-2.0) AND GPL-3.0 must violate on GPL-3.0, got ok=%v off=%v", ok, off)
	}
	// The choice group is satisfied by MIT and the mandatory operand is allowed →
	// whole expression allowed.
	if ok, _ := EvaluateExpression("(MIT OR GPL-3.0) AND Apache-2.0", denied); !ok {
		t.Error("(MIT OR GPL-3.0) AND Apache-2.0 should be allowed (MIT satisfies the OR, Apache allowed)")
	}
	// Nested: an inner AND with a denied operand, OR'd with an allowed leaf → the
	// allowed leaf satisfies the top-level OR.
	if ok, _ := EvaluateExpression("(GPL-3.0 AND MIT) OR Apache-2.0", denied); !ok {
		t.Error("(GPL-3.0 AND MIT) OR Apache-2.0 should be allowed (Apache satisfies the OR)")
	}
	// Same shape, but the only alternative is also denied → violation.
	if ok, _ := EvaluateExpression("(GPL-3.0 AND MIT) OR GPL-2.0", denied); ok {
		t.Error("(GPL-3.0 AND MIT) OR GPL-2.0 should violate (both branches denied)")
	}
}

// TestEvaluateExpression_WithExceptionPair verifies a license+exception pair can
// be denied as a unit without denying the bare license.
func TestEvaluateExpression_WithExceptionPair(t *testing.T) {
	// Deny only the specific pair, not bare GPL-2.0.
	denied := map[string]struct{}{"gpl-2.0 with classpath-exception-2.0": {}}
	if ok, _ := EvaluateExpression("GPL-2.0-only WITH Classpath-exception-2.0", denied); ok {
		t.Error("the denied license+exception pair should violate")
	}
	if ok, _ := EvaluateExpression("GPL-2.0-only", denied); !ok {
		t.Error("bare GPL-2.0 should be allowed when only the pair is denied")
	}
}

func TestPolicyEvaluate(t *testing.T) {
	policy := LicensePolicy{DeniedCategories: []LicenseCategory{CategoryStrongCopyleft}}

	tests := []struct {
		name    string
		pkg     PackageLicense
		wantVio bool
	}{
		{"permissive ok", PackageLicense{Package: "a", Licenses: []string{"MIT"}}, false},
		{"strong copyleft denied", PackageLicense{Package: "b", Licenses: []string{"GPL-3.0"}}, true},
		{"OR-expr with permissive ok", PackageLicense{Package: "c", Licenses: []string{"MIT OR GPL-3.0"}}, false},
		// Separate entries are a CONJUNCTION (the package is bound by both), so a
		// single denied entry violates even alongside a permissive one.
		{"multi-entry conjunction violates", PackageLicense{Package: "d", Licenses: []string{"GPL-3.0", "MIT"}}, true},
		{"multi-entry all permissive ok", PackageLicense{Package: "d2", Licenses: []string{"MIT", "BSD-3-Clause"}}, false},
		{"multi-entry all denied", PackageLicense{Package: "e", Licenses: []string{"GPL-2.0", "GPL-3.0"}}, true},
		{"no license, unknown not denied", PackageLicense{Package: "f"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vio, reason := policy.Evaluate(tc.pkg)
			if vio != tc.wantVio {
				t.Errorf("Evaluate = %v (%q), want %v", vio, reason, tc.wantVio)
			}
		})
	}
}

func TestPolicyExceptions(t *testing.T) {
	// Deny strong-copyleft but allow one specific GPL library.
	policy := LicensePolicy{
		DeniedCategories: []LicenseCategory{CategoryStrongCopyleft},
		AllowExceptions:  []string{"GPL-2.0"},
	}
	if vio, _ := policy.Evaluate(PackageLicense{Package: "a", Licenses: []string{"GPL-2.0"}}); vio {
		t.Error("GPL-2.0 with allow-exception should be compliant")
	}
	if vio, _ := policy.Evaluate(PackageLicense{Package: "b", Licenses: []string{"GPL-3.0"}}); !vio {
		t.Error("GPL-3.0 (not excepted) should violate")
	}

	// Deny-exception flags an otherwise-permissive license.
	deny := LicensePolicy{DenyExceptions: []string{"MIT"}}
	if vio, _ := deny.Evaluate(PackageLicense{Package: "c", Licenses: []string{"MIT"}}); !vio {
		t.Error("MIT with deny-exception should violate")
	}
}

// TestPolicyWithExceptionPair verifies a pair-specific allow-exception: deny a
// category in general, but permit a license ONLY when it carries a specific WITH
// exception. The flat-set path could not express this (the bare license was
// denied regardless of the exception).
func TestPolicyWithExceptionPair(t *testing.T) {
	policy := LicensePolicy{
		DeniedCategories: []LicenseCategory{CategoryStrongCopyleft},
		AllowExceptions:  []string{"GPL-3.0-only WITH Classpath-exception-2.0"},
	}
	// The excepted pair is allowed...
	if vio, reason := policy.Evaluate(PackageLicense{
		Package: "a", Licenses: []string{"GPL-3.0-only WITH Classpath-exception-2.0"},
	}); vio {
		t.Errorf("GPL-3.0 WITH the allowed exception should be compliant, got violation: %q", reason)
	}
	// ...but bare GPL-3.0 (no exception) still violates the category.
	if vio, _ := policy.Evaluate(PackageLicense{Package: "b", Licenses: []string{"GPL-3.0-only"}}); !vio {
		t.Error("bare GPL-3.0 (no exception) should still violate")
	}
	// ...and GPL-3.0 with a DIFFERENT exception still violates.
	if vio, _ := policy.Evaluate(PackageLicense{
		Package: "c", Licenses: []string{"GPL-3.0-only WITH GCC-exception-3.1"},
	}); !vio {
		t.Error("GPL-3.0 with a non-allowed exception should violate")
	}
}

// TestPolicyMalformedIsUnknown verifies a malformed SPDX entry is treated as
// unknown (a data-quality signal), not turned into a partial verdict: it violates
// only when the policy denies the unknown category, and never manufactures an
// allow/deny from a broken expression.
func TestPolicyMalformedIsUnknown(t *testing.T) {
	malformed := []string{"MIT OR", "(GPL-3.0", "MIT garbage-token", "AND", "GPL-2.0 WITH"}

	// Policy denies strong-copyleft but NOT unknown: a malformed entry must NOT be
	// read as a denied GPL (e.g. "(GPL-3.0" must not manufacture a violation), and
	// must NOT be read as an allowed MIT either — it is simply unknown ⇒ no
	// violation here.
	noUnknown := LicensePolicy{DeniedCategories: []LicenseCategory{CategoryStrongCopyleft}}
	for _, entry := range malformed {
		if vio, reason := noUnknown.Evaluate(PackageLicense{Package: "a", Licenses: []string{entry}}); vio {
			t.Errorf("malformed %q must not manufacture a violation (unknown not denied), got %q", entry, reason)
		}
	}

	// Policy denies unknown: every malformed entry now violates as unparseable.
	denyUnknown := LicensePolicy{DeniedCategories: []LicenseCategory{CategoryUnknown}}
	for _, entry := range malformed {
		if vio, _ := denyUnknown.Evaluate(PackageLicense{Package: "b", Licenses: []string{entry}}); !vio {
			t.Errorf("malformed %q should violate when unknown is denied", entry)
		}
	}
}

func TestPolicyUnknownDenied(t *testing.T) {
	policy := LicensePolicy{DeniedCategories: []LicenseCategory{CategoryUnknown}}
	if vio, _ := policy.Evaluate(PackageLicense{Package: "a"}); !vio {
		t.Error("no-license package should violate when unknown is denied")
	}
	if vio, _ := policy.Evaluate(PackageLicense{Package: "b", Licenses: []string{"NOASSERTION"}}); !vio {
		t.Error("NOASSERTION should violate when unknown is denied")
	}
}

func TestEmptyPolicyDeniesNothing(t *testing.T) {
	var policy LicensePolicy
	if vio, _ := policy.Evaluate(PackageLicense{Package: "a", Licenses: []string{"GPL-3.0"}}); vio {
		t.Error("empty policy must deny nothing")
	}
}

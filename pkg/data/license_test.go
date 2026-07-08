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
	}
	for in, want := range cases {
		if got := Classify(in); got != want {
			t.Errorf("Classify(%q) = %q, want %q", in, got, want)
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

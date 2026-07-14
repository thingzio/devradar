package postgres

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestAuditRepositoryTargetPreservesOnlyValidRawValues(t *testing.T) {
	valid := "registry.test/team/app"
	if got := auditRepositoryTarget(valid); got != valid {
		t.Fatalf("valid repository target = %q, want raw %q", got, valid)
	}

	for _, repository := range []string{
		"", " leading", "trailing ", strings.Repeat("界", maxAuditTargetIDChars+1),
	} {
		sum := sha256.Sum256([]byte(repository))
		want := "sha256:" + hex.EncodeToString(sum[:])
		if got := auditRepositoryTarget(repository); got != want {
			t.Fatalf("invalid repository target for %q = %q, want %q", repository, got, want)
		}
	}
}

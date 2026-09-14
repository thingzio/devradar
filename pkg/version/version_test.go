package version

import (
	"runtime/debug"
	"testing"
)

func TestGetPrefersLdflags(t *testing.T) {
	t.Cleanup(func() { version, commit, date = "", "", "" })
	version, commit, date = "v9.9.9", "deadbee", "2026-01-01T00:00:00Z"

	got := Get()
	if got.Version != "v9.9.9" || got.Commit != "deadbee" || got.Date != "2026-01-01T00:00:00Z" {
		t.Fatalf("ldflags not preferred, got %+v", got)
	}
}

func TestFromBuildInfo(t *testing.T) {
	tests := []struct {
		name       string
		mainVer    string
		wantVer    string
		wantCommit string
	}{
		{"release tag", "v1.2.3", "v1.2.3", "34d35be"},
		{"prerelease tag", "v1.2.3-rc.1", "v1.2.3-rc.1", "34d35be"},
		{"pseudo version", "v0.0.0-20260914113748-342607f5485a", "", "34d35be"},
		{"dirty tag", "v1.2.3+dirty", "", "34d35be"},
		{"devel", "(devel)", "", "34d35be"},
		{"empty", "", "", "34d35be"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bi := &debug.BuildInfo{
				Main: debug.Module{Version: tc.mainVer},
				Settings: []debug.BuildSetting{
					{Key: "vcs.revision", Value: "34d35be0c4fd906066b553f49c680e3483d3d8bb"},
					{Key: "vcs.time", Value: "2026-09-14T11:39:01Z"},
				},
			}
			got := fromBuildInfo(bi)
			if got.Version != tc.wantVer {
				t.Errorf("Version = %q, want %q", got.Version, tc.wantVer)
			}
			if got.Commit != tc.wantCommit {
				t.Errorf("Commit = %q, want %q", got.Commit, tc.wantCommit)
			}
			if got.Date != "2026-09-14T11:39:01Z" {
				t.Errorf("Date = %q", got.Date)
			}
		})
	}
}

func TestFromBuildInfoWithoutVCS(t *testing.T) {
	bi := &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}}
	got := fromBuildInfo(bi)
	if got.Version != "v1.2.3" {
		t.Errorf("Version = %q, want v1.2.3", got.Version)
	}
	if got.Commit != "" || got.Date != "" {
		t.Errorf("expected empty commit/date, got %+v", got)
	}
}

package account_test

import (
	"testing"

	"github.com/thingzio/devradar/pkg/account"
)

func TestRoleCapabilities(t *testing.T) {
	capabilities := []account.Capability{
		account.ReadAccount,
		account.WritePersonal,
		account.WriteEvidence,
		account.ManageSettings,
		account.ManageCredentials,
		account.ManageMembers,
	}
	tests := []struct {
		role account.Role
		want map[account.Capability]bool
	}{
		{
			role: account.RoleAdmin,
			want: map[account.Capability]bool{
				account.ReadAccount:       true,
				account.WritePersonal:     true,
				account.WriteEvidence:     true,
				account.ManageSettings:    true,
				account.ManageCredentials: true,
				account.ManageMembers:     true,
			},
		},
		{
			role: account.RoleEditor,
			want: map[account.Capability]bool{
				account.ReadAccount:       true,
				account.WritePersonal:     true,
				account.WriteEvidence:     true,
				account.ManageSettings:    false,
				account.ManageCredentials: false,
				account.ManageMembers:     false,
			},
		},
		{
			role: account.RoleReader,
			want: map[account.Capability]bool{
				account.ReadAccount:       true,
				account.WritePersonal:     true,
				account.WriteEvidence:     false,
				account.ManageSettings:    false,
				account.ManageCredentials: false,
				account.ManageMembers:     false,
			},
		},
		{role: account.Role("owner"), want: map[account.Capability]bool{}},
	}
	for _, tt := range tests {
		for _, capability := range capabilities {
			if got, want := tt.role.Can(capability), tt.want[capability]; got != want {
				t.Errorf("%s.Can(%s) = %v, want %v", tt.role, capability, got, want)
			}
		}
		if tt.role.Can(account.Capability("account.delete")) {
			t.Errorf("%s must not grant an unknown capability", tt.role)
		}
	}
}

func TestRoleValid(t *testing.T) {
	for _, role := range []account.Role{account.RoleAdmin, account.RoleEditor, account.RoleReader} {
		if !role.Valid() {
			t.Fatalf("%s.Valid() = false, want true", role)
		}
	}
	if account.Role("owner").Valid() {
		t.Fatal("unknown role must not be valid")
	}
}

func TestAccessCanDelegatesToMembershipRole(t *testing.T) {
	access := account.Access{Membership: account.Membership{Role: account.RoleEditor}}
	if !access.Can(account.WriteEvidence) {
		t.Fatal("editor access must permit evidence writes")
	}
	if access.Can(account.ManageSettings) {
		t.Fatal("editor access must not permit settings management")
	}
}

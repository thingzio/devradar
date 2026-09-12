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

package server

import (
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
)

type accountsView struct {
	chromeView
	Accounts  []account.Access
	CSRFToken string
	Error     string
	Left      bool
}

type accountSettingsView struct {
	chromeView
	CSRFToken string
	Renamed   bool
}

type accountMembersView struct {
	chromeView
	Members        []account.Access
	Invitations    []postgres.Invitation
	SharingEnabled bool
	CSRFToken      string
	Message        string
}

func (s *Server) handleAccounts(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	accounts, err := s.store.ListUserAccounts(r.Context(), user.ID)
	if err != nil {
		slog.Error("list user accounts", "user_id", user.ID,
			"request_id", middleware.RequestIDFromContext(r.Context()), "error", err)
		http.Error(w, "failed to list accounts", http.StatusInternalServerError)
		return
	}
	render(w, "accounts.html", accountsView{
		chromeView: s.userChrome(user, "Accounts", ""), Accounts: accounts,
		CSRFToken: issueCSRF(w), Error: r.URL.Query().Get("error"),
		Left: r.URL.Query().Get("msg") == "left",
	})
}

func (s *Server) handleSelectAccount(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())
	accountID := strings.TrimSpace(r.FormValue("account_id"))
	cookie, err := r.Cookie(middleware.SessionCookieName())
	if !validUUID(accountID) || err != nil {
		logMutationDenied(r, "account.select", "missing account or session")
		http.Redirect(w, r, "/accounts?error=unavailable", http.StatusSeeOther)
		return
	}
	if err := s.store.SelectSessionAccount(r.Context(), cookie.Value, user.ID, accountID); err != nil {
		if errors.Is(err, postgres.ErrNotFound) {
			logMutationDenied(r, "account.select", "membership unavailable")
			http.Redirect(w, r, "/accounts?error=unavailable", http.StatusSeeOther)
			return
		}
		logMutationFailure(r, "account.select", accountID, user.ID, err)
		http.Error(w, "failed to select account", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/overview", http.StatusSeeOther)
}

func (s *Server) handleLeaveAccount(w http.ResponseWriter, r *http.Request) {
	accountID := r.PathValue("id")
	if !validUUID(accountID) {
		logMutationDenied(r, "membership.leave", "invalid account identifier")
		http.NotFound(w, r)
		return
	}
	actor := middleware.ActorFromContext(r.Context())
	err := s.store.LeaveAccountAudited(r.Context(), accountID, actor,
		middleware.RequestIDFromContext(r.Context()))
	if err != nil {
		writeAccountMutationError(w, r, "membership.leave", accountID, actor.UserID, err)
		return
	}
	s.clearSelectedAccountBestEffort(r, actor.UserID, accountID)
	http.Redirect(w, r, "/accounts?msg=left", http.StatusSeeOther)
}

func (s *Server) handleAccountSettings(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	render(w, "account_settings.html", accountSettingsView{
		chromeView: s.chrome(access, "Account settings", ""), CSRFToken: issueCSRF(w),
		Renamed: r.URL.Query().Get("msg") == "renamed",
	})
}

func (s *Server) handleUpdateAccountName(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" || utf8.RuneCountInString(name) > 80 {
		logMutationDenied(r, "account.name.update", "invalid account name")
		http.Error(w, "account name must be 1-80 characters", http.StatusBadRequest)
		return
	}
	if err := s.store.UpdateAccountNameAudited(r.Context(), access.Account.ID, name,
		middleware.ActorFromContext(r.Context()), middleware.RequestIDFromContext(r.Context())); err != nil {
		writeAccountMutationError(w, r, "account.name.update", access.Account.ID, access.Account.ID, err)
		return
	}
	http.Redirect(w, r, "/account/settings?msg=renamed", http.StatusSeeOther)
}

func (s *Server) handleAccountMembers(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	members, err := s.store.ListMembers(r.Context(), access.Account.ID)
	if err != nil {
		logMutationFailure(r, "membership.list", access.Account.ID, access.Account.ID, err)
		http.Error(w, "failed to list account members", http.StatusInternalServerError)
		return
	}
	var invitations []postgres.Invitation
	sharingEnabled := config.AccountSharingEnabled()
	if sharingEnabled {
		invitations, err = s.store.ListInvitations(r.Context(), access.Account.ID)
		if err != nil {
			logMutationFailure(r, "invitation.list", access.Account.ID, access.Account.ID, err)
			http.Error(w, "failed to list account invitations", http.StatusInternalServerError)
			return
		}
	}
	render(w, "account_members.html", accountMembersView{
		chromeView: s.chrome(access, "Account members", ""), Members: members, Invitations: invitations,
		SharingEnabled: sharingEnabled, CSRFToken: issueCSRF(w), Message: r.URL.Query().Get("msg"),
	})
}

func (s *Server) handleChangeMemberRole(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	targetUserID := r.PathValue("id")
	if !validUUID(targetUserID) {
		logMutationDenied(r, "membership.role_change", "invalid member identifier")
		http.NotFound(w, r)
		return
	}
	role := account.Role(r.FormValue("role"))
	if !role.Valid() {
		logMutationDenied(r, "membership.role_change", "invalid role")
		http.Error(w, "invalid account role", http.StatusBadRequest)
		return
	}
	err := s.store.ChangeMemberRoleAudited(r.Context(), access.Account.ID, targetUserID, role,
		middleware.ActorFromContext(r.Context()), middleware.RequestIDFromContext(r.Context()))
	if err != nil {
		writeAccountMutationError(w, r, "membership.role_change", access.Account.ID, targetUserID, err)
		return
	}
	if targetUserID == access.Actor.ID && role != account.RoleAdmin {
		http.Redirect(w, r, "/overview", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/account/members?msg=changed", http.StatusSeeOther)
}

func (s *Server) handleRevokeMembership(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	targetUserID := r.PathValue("id")
	if !validUUID(targetUserID) {
		logMutationDenied(r, "membership.revoke", "invalid member identifier")
		http.NotFound(w, r)
		return
	}
	err := s.store.RevokeMembershipAudited(r.Context(), access.Account.ID, targetUserID,
		middleware.ActorFromContext(r.Context()), middleware.RequestIDFromContext(r.Context()))
	if err != nil {
		writeAccountMutationError(w, r, "membership.revoke", access.Account.ID, targetUserID, err)
		return
	}
	if targetUserID == access.Actor.ID {
		s.clearSelectedAccountBestEffort(r, access.Actor.ID, access.Account.ID)
		http.Redirect(w, r, "/accounts?msg=left", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/account/members?msg=changed", http.StatusSeeOther)
}

func (s *Server) clearSelectedAccountBestEffort(r *http.Request, userID, accountID string) {
	cookie, err := r.Cookie(middleware.SessionCookieName())
	if err != nil {
		slog.Error("clear selected account", "user_id", userID, "account_id", accountID,
			"path", r.URL.Path, "request_id", middleware.RequestIDFromContext(r.Context()), "error", err)
		return
	}
	if _, err := s.store.ClearSessionAccount(r.Context(), cookie.Value, userID, accountID); err != nil {
		slog.Error("clear selected account", "user_id", userID, "account_id", accountID,
			"path", r.URL.Path, "request_id", middleware.RequestIDFromContext(r.Context()), "error", err)
	}
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := value[:8] + value[9:13] + value[14:18] + value[19:23] + value[24:]
	_, err := hex.DecodeString(compact)
	return err == nil
}

func writeAccountMutationError(
	w http.ResponseWriter,
	r *http.Request,
	action, accountID, targetID string,
	err error,
) {
	switch {
	case errors.Is(err, postgres.ErrLastAdmin):
		logMutationDenied(r, action, "last active admin")
		http.Error(w, "Add or promote another admin before making this change.", http.StatusConflict)
	case errors.Is(err, postgres.ErrNotFound):
		logMutationDenied(r, action, "account or membership not found")
		http.NotFound(w, r)
	case errors.Is(err, postgres.ErrForbidden):
		logMutationDenied(r, action, "admin role required")
		http.Error(w, "Forbidden", http.StatusForbidden)
	default:
		logMutationFailure(r, action, accountID, targetID, err)
		http.Error(w, "account update failed", http.StatusInternalServerError)
	}
}

package server

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/thingzio/devradar/pkg/account"
	"github.com/thingzio/devradar/pkg/authn"
	"github.com/thingzio/devradar/pkg/config"
	"github.com/thingzio/devradar/pkg/data/postgres"
	"github.com/thingzio/devradar/pkg/middleware"
	"github.com/thingzio/devradar/pkg/ratelimit"
)

type accountInvitationView struct {
	Title         string
	Version       string
	Invitation    *postgres.Invitation
	RoleLabel     string
	SignedInEmail string
	CSRFToken     string
	Error         string
}

func (s *Server) handleInvitation(w http.ResponseWriter, r *http.Request) {
	invitationID := r.PathValue("id")
	if !validUUID(invitationID) {
		http.NotFound(w, r)
		return
	}
	invitation, err := s.store.PeekInvitation(r.Context(), invitationID)
	if err != nil {
		status := http.StatusNotFound
		message := "This invitation is invalid or no longer available."
		if errors.Is(err, postgres.ErrInvitationExpired) {
			status = http.StatusGone
			message = "This invitation expired. Ask an account admin to send it again."
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		render(w, "account_invitation.html", accountInvitationView{
			Title: "Account invitation", Version: s.opts.Version, Error: message,
		})
		return
	}
	view := accountInvitationView{
		Title: "Account invitation", Version: s.opts.Version, Invitation: invitation,
		RoleLabel: invitationRoleLabel(invitation.Role), CSRFToken: issueCSRF(w),
	}
	if user := s.optionalInvitationUser(r); user != nil {
		view.SignedInEmail = user.Email
	}
	render(w, "account_invitation.html", view)
}

func (s *Server) handleAcceptInvitation(w http.ResponseWriter, r *http.Request) {
	invitationID := r.PathValue("id")
	if !validUUID(invitationID) {
		http.NotFound(w, r)
		return
	}
	var signedUserID string
	if user := s.optionalInvitationUser(r); user != nil {
		signedUserID = user.ID
	}
	user, acct, consumed, err := s.store.AcceptInvitation(r.Context(), invitationID,
		r.FormValue("token"), signedUserID,
		middleware.RequestIDFromContext(r.Context()))
	if err != nil {
		switch {
		case errors.Is(err, postgres.ErrInvitationEmailMismatch):
			http.Error(w, "You are signed in with a different email. Sign out, then open the invitation again.", http.StatusConflict)
		case errors.Is(err, postgres.ErrInvitationExpired):
			http.Error(w, "This invitation expired. Ask an account admin to send it again.", http.StatusGone)
		case errors.Is(err, postgres.ErrInvitationInvalid), errors.Is(err, postgres.ErrNotFound):
			http.NotFound(w, r)
		case errors.Is(err, postgres.ErrForbidden):
			http.Error(w, "This account or user is not available.", http.StatusForbidden)
		default:
			slog.Error("accept invitation", "request_id", middleware.RequestIDFromContext(r.Context()), "error", err)
			http.Error(w, "Invitation acceptance failed. Try again.", http.StatusInternalServerError)
		}
		return
	}
	if !consumed {
		if signedUserID == "" {
			http.Error(w, "This invitation was already accepted. Sign in to continue.", http.StatusConflict)
			return
		}
		cookie, cookieErr := r.Cookie(middleware.SessionCookieName())
		if cookieErr != nil {
			http.Error(w, "This invitation was already accepted. Sign in to continue.", http.StatusConflict)
			return
		}
		if err := s.store.SelectSessionAccount(r.Context(), cookie.Value, user.ID, acct.ID); err != nil {
			slog.Error("select accepted invitation account", "user_id", user.ID, "account_id", acct.ID,
				"request_id", middleware.RequestIDFromContext(r.Context()), "error", err)
			http.Error(w, "This invitation was already accepted. Sign in to continue.", http.StatusConflict)
			return
		}
		http.Redirect(w, r, "/overview", http.StatusFound)
		return
	}
	// Membership acceptance is already committed. Session failure cannot undo
	// access; the recipient can sign in normally and select the account later.
	session, err := s.store.CreateSession(r.Context(), user.ID, &acct.ID, sessionTTL)
	if err != nil {
		slog.Error("create accepted invitation session", "user_id", user.ID, "account_id", acct.ID,
			"request_id", middleware.RequestIDFromContext(r.Context()), "error", err)
		http.Error(w, "Access was accepted. Sign in to continue.", http.StatusInternalServerError)
		return
	}
	middleware.SetSessionCookie(w, session, int(sessionTTL.Seconds()))
	http.Redirect(w, r, "/overview", http.StatusFound)
}

func (s *Server) optionalInvitationUser(r *http.Request) *account.User {
	cookie, err := r.Cookie(middleware.SessionCookieName())
	if err != nil {
		return nil
	}
	session, err := s.store.ValidateSession(r.Context(), cookie.Value)
	if err != nil || session.User.Status != "active" {
		return nil
	}
	return &session.User
}

func (s *Server) handleCreateInvitation(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	email := authn.NormalizeEmail(r.FormValue("email"))
	role := account.Role(r.FormValue("role"))
	if !looksLikeEmail(email) || !role.Valid() {
		http.Error(w, "Enter a valid email and role.", http.StatusBadRequest)
		return
	}
	access := middleware.AccessFromContext(r.Context())
	if err := allowInvitationSend(r.Context(), s.store.DB(), access.Account.ID, email); err != nil {
		logMutationDenied(r, "invitation.create", "rate limit denied")
		http.Error(w, "Invitation sending is temporarily unavailable. Try again later.", http.StatusTooManyRequests)
		return
	}
	key, err := config.DeliveryKey()
	if err != nil {
		logMutationFailure(r, "invitation.create", access.Account.ID, email, err)
		http.Error(w, "Invitation sending is unavailable.", http.StatusInternalServerError)
		return
	}
	_, err = s.store.CreateOrRefreshInvitation(r.Context(), access.Account.ID, email, role,
		middleware.ActorFromContext(r.Context()), middleware.RequestIDFromContext(r.Context()), key)
	if err != nil {
		writeInvitationMutationError(w, r, "invitation.create", access.Account.ID, email, err)
		return
	}
	http.Redirect(w, r, "/account/members?msg=invited", http.StatusSeeOther)
}

func (s *Server) handleChangeInvitationRole(w http.ResponseWriter, r *http.Request) {
	role := account.Role(r.FormValue("role"))
	if !role.Valid() || !validUUID(r.PathValue("id")) {
		http.Error(w, "Invalid invitation or role.", http.StatusBadRequest)
		return
	}
	access := middleware.AccessFromContext(r.Context())
	email, err := pendingInvitationEmail(r.Context(), s.store, access.Account.ID, r.PathValue("id"))
	if err != nil {
		writeInvitationMutationError(w, r, "invitation.role_change", access.Account.ID, r.PathValue("id"), err)
		return
	}
	if err := allowInvitationSend(r.Context(), s.store.DB(), access.Account.ID, email); err != nil {
		http.Error(w, "Invitation sending is temporarily unavailable. Try again later.", http.StatusTooManyRequests)
		return
	}
	key, err := config.DeliveryKey()
	if err != nil {
		http.Error(w, "Invitation sending is unavailable.", http.StatusInternalServerError)
		return
	}
	_, err = s.store.ChangeInvitationRole(r.Context(), access.Account.ID, r.PathValue("id"), role,
		middleware.ActorFromContext(r.Context()), middleware.RequestIDFromContext(r.Context()), key)
	if err != nil {
		writeInvitationMutationError(w, r, "invitation.role_change", access.Account.ID, r.PathValue("id"), err)
		return
	}
	http.Redirect(w, r, "/account/members?msg=changed", http.StatusSeeOther)
}

func (s *Server) handleResendInvitation(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	id := r.PathValue("id")
	if !validUUID(id) {
		http.NotFound(w, r)
		return
	}
	email, err := pendingInvitationEmail(r.Context(), s.store, access.Account.ID, id)
	if err != nil {
		writeInvitationMutationError(w, r, "invitation.resend", access.Account.ID, id, err)
		return
	}
	if err := allowInvitationSend(r.Context(), s.store.DB(), access.Account.ID, email); err != nil {
		http.Error(w, "Invitation sending is temporarily unavailable. Try again later.", http.StatusTooManyRequests)
		return
	}
	key, err := config.DeliveryKey()
	if err != nil {
		http.Error(w, "Invitation sending is unavailable.", http.StatusInternalServerError)
		return
	}
	_, err = s.store.ResendInvitation(r.Context(), access.Account.ID, id,
		middleware.ActorFromContext(r.Context()), middleware.RequestIDFromContext(r.Context()), key)
	if err != nil {
		writeInvitationMutationError(w, r, "invitation.resend", access.Account.ID, id, err)
		return
	}
	http.Redirect(w, r, "/account/members?msg=resent", http.StatusSeeOther)
}

func (s *Server) handleRevokeInvitation(w http.ResponseWriter, r *http.Request) {
	access := middleware.AccessFromContext(r.Context())
	id := r.PathValue("id")
	if !validUUID(id) {
		http.NotFound(w, r)
		return
	}
	if err := s.store.RevokeInvitation(r.Context(), access.Account.ID, id,
		middleware.ActorFromContext(r.Context()), middleware.RequestIDFromContext(r.Context())); err != nil {
		writeInvitationMutationError(w, r, "invitation.revoke", access.Account.ID, id, err)
		return
	}
	http.Redirect(w, r, "/account/members?msg=changed", http.StatusSeeOther)
}

func allowInvitationSend(ctx context.Context, db *sql.DB, accountID, email string) error {
	allowed, err := ratelimit.Allow(ctx, db, "invitation-account:"+accountID,
		config.InvitationRatePerHourAccount(), time.Hour)
	if err != nil || !allowed {
		if err != nil {
			return err
		}
		return postgres.ErrRateLimited
	}
	allowed, err = ratelimit.Allow(ctx, db, "invitation-recipient:"+email,
		config.InvitationRatePerHourRecipient(), time.Hour)
	if err != nil || !allowed {
		if err != nil {
			return err
		}
		return postgres.ErrRateLimited
	}
	return nil
}

func pendingInvitationEmail(ctx context.Context, store *postgres.Store, accountID, invitationID string) (string, error) {
	invitations, err := store.ListInvitations(ctx, accountID)
	if err != nil {
		return "", err
	}
	for _, invitation := range invitations {
		if invitation.ID == invitationID {
			return invitation.Email, nil
		}
	}
	return "", postgres.ErrNotFound
}

func writeInvitationMutationError(w http.ResponseWriter, r *http.Request, action, accountID, targetID string, err error) {
	switch {
	case errors.Is(err, postgres.ErrRateLimited):
		http.Error(w, "Wait at least one minute before sending this invitation again.", http.StatusTooManyRequests)
	case errors.Is(err, postgres.ErrActiveMember):
		http.Error(w, "That person already has access to this account.", http.StatusConflict)
	case errors.Is(err, postgres.ErrNotFound):
		http.NotFound(w, r)
	case errors.Is(err, postgres.ErrForbidden):
		http.Error(w, "Forbidden", http.StatusForbidden)
	default:
		logMutationFailure(r, action, accountID, targetID, err)
		http.Error(w, "Invitation update failed.", http.StatusInternalServerError)
	}
}

func invitationRoleLabel(role account.Role) string {
	value := string(role)
	if value == "" {
		return ""
	}
	return strings.ToUpper(value[:1]) + value[1:]
}

package server

import "github.com/thingzio/devradar/pkg/account"

type chromeView struct {
	Title       string
	SignedIn    bool
	Tab         string
	Email       string
	AvatarURL   string
	AccountName string
	AccountRole account.Role
	Version     string
}

func (s *Server) chrome(access *account.Access, title, tab string) chromeView {
	view := chromeView{Title: title, Tab: tab, Version: s.opts.Version}
	if access == nil {
		return view
	}
	view.SignedIn = true
	view.Email = access.Actor.Email
	view.AvatarURL = access.Actor.AvatarURL
	view.AccountName = access.Account.Name
	view.AccountRole = access.Membership.Role
	return view
}

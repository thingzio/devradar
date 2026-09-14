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

import "github.com/thingzio/devradar/pkg/account"

type chromeView struct {
	Title                string
	SignedIn             bool
	HasAccount           bool
	Tab                  string
	Email                string
	AvatarURL            string
	AccountName          string
	AccountRole          account.Role
	CanReadAccount       bool
	CanWritePersonal     bool
	CanWriteEvidence     bool
	CanManageSettings    bool
	CanManageCredentials bool
	CanManageMembers     bool
	Version              string
	Commit               string
}

func (s *Server) chrome(access *account.Access, title, tab string) chromeView {
	view := chromeView{Title: title, Tab: tab, Version: s.opts.Version, Commit: s.opts.Commit}
	if access == nil {
		return view
	}
	view.SignedIn = true
	view.HasAccount = true
	view.Email = access.Actor.Email
	view.AvatarURL = access.Actor.AvatarURL
	view.AccountName = access.Account.Name
	view.AccountRole = access.Membership.Role
	view.CanReadAccount = access.Can(account.ReadAccount)
	view.CanWritePersonal = access.Can(account.WritePersonal)
	view.CanWriteEvidence = access.Can(account.WriteEvidence)
	view.CanManageSettings = access.Can(account.ManageSettings)
	view.CanManageCredentials = access.Can(account.ManageCredentials)
	view.CanManageMembers = access.Can(account.ManageMembers)
	return view
}

func (s *Server) userChrome(user *account.User, title, tab string) chromeView {
	view := chromeView{Title: title, SignedIn: true, Tab: tab, Version: s.opts.Version, Commit: s.opts.Commit}
	if user != nil {
		view.Email = user.Email
		view.AvatarURL = user.AvatarURL
	}
	return view
}

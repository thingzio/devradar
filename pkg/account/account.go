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

// Package account defines account identity and authorization domain types.
package account

import "time"

// Role identifies a membership's account-wide authorization role.
type Role string

const (
	RoleAdmin  Role = "admin"
	RoleEditor Role = "editor"
	RoleReader Role = "reader"
)

// Capability identifies an account operation that a role may perform.
type Capability string

const (
	ReadAccount       Capability = "account.read"
	WritePersonal     Capability = "personal.write"
	WriteEvidence     Capability = "evidence.write"
	ManageSettings    Capability = "settings.manage"
	ManageCredentials Capability = "credentials.manage"
	ManageMembers     Capability = "members.manage"
)

// Valid reports whether r is a supported account role.
func (r Role) Valid() bool {
	return r == RoleAdmin || r == RoleEditor || r == RoleReader
}

// Can reports whether r grants c.
func (r Role) Can(c Capability) bool {
	switch r {
	case RoleAdmin:
		return c == ReadAccount || c == WritePersonal || c == WriteEvidence ||
			c == ManageSettings || c == ManageCredentials || c == ManageMembers
	case RoleEditor:
		return c == ReadAccount || c == WritePersonal || c == WriteEvidence
	case RoleReader:
		return c == ReadAccount || c == WritePersonal
	default:
		return false
	}
}

// User is an authenticated person independent of any account.
type User struct {
	ID              string
	Email           string
	EmailVerifiedAt *time.Time
	Status          string
	AvatarURL       string
	TOSAcceptedAt   *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Account owns DevRadar evidence, policy, and credentials.
type Account struct {
	ID          string
	Name        string
	Plan        string
	Status      string
	MinSeverity string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Membership grants a user a role in an account.
type Membership struct {
	AccountID       string
	UserID          string
	Role            Role
	CreatedByUserID *string
	AcceptedAt      time.Time
	RevokedAt       *time.Time
	RevokedByUserID *string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Access is a browser user's active account authorization context.
type Access struct {
	Actor      User
	Account    Account
	Membership Membership
}

// Can reports whether the active membership grants c.
func (a Access) Can(c Capability) bool {
	return a.Membership.Role.Can(c)
}

// ActorKind identifies the principal responsible for an action.
type ActorKind string

const (
	ActorUser     ActorKind = "user"
	ActorAPIToken ActorKind = "api_token"
	ActorPlatform ActorKind = "platform"
)

// Actor identifies a user, API token, or platform principal.
type Actor struct {
	Kind       ActorKind
	UserID     string
	APITokenID string
}

// VerifiedIdentity is identity-provider data whose ownership was verified.
type VerifiedIdentity struct {
	Provider  string
	Subject   string
	Email     string
	AvatarURL string
}

// Session authenticates a user and optionally selects one active account.
type Session struct {
	User            User
	ActiveAccountID *string
	ExpiresAt       time.Time
}

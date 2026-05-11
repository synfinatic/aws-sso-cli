package sso

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2026 Aaron Turner  <synfinatic at gmail dot com>
 *
 * This program is free software: you can redistribute it
 * and/or modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or with the authors permission any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import "github.com/synfinatic/aws-sso-cli/internal/uri"

// RoleProvider is the interface that wraps the AWS SSO role-fetching operations.
// *AWSSSO satisfies this interface.
type RoleProvider interface {
	GetAccounts() ([]AccountInfo, error)
	GetRoles(account AccountInfo) ([]RoleInfo, error)
}

// Authenticator is the interface that wraps AWS SSO authentication operations.
// *AWSSSO satisfies this interface.
type Authenticator interface {
	Authenticate(urlAction uri.Action, browser string) error
	ValidAuthToken() bool
	Logout() error
}

// Compile-time assertions that *AWSSSO satisfies both interfaces.
var _ RoleProvider = (*AWSSSO)(nil)
var _ Authenticator = (*AWSSSO)(nil)

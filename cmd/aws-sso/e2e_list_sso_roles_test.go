//go:build e2etests

package main

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

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/synfinatic/aws-sso-cli/internal/awsmock"
)

// TestE2EListSSORoles verifies the happy path: accounts and roles returned by the
// mock server appear in the output table.
func TestE2EListSSORoles(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)

	setup.Server.SSO.QueueListAccounts(awsmock.ListAccountsResponse{
		AccountList: []awsmock.AccountInfo{
			{AccountID: "123456789012", AccountName: "TestAccount", EmailAddress: "admin@example.com"},
		},
	})
	setup.Server.SSO.QueueListAccountRoles(awsmock.ListAccountRolesResponse{
		RoleList: []awsmock.RoleInfo{
			{AccountID: "123456789012", RoleName: "ReadOnly"},
			{AccountID: "123456789012", RoleName: "PowerUser"},
		},
	})

	ctx := newRunContext(setup, AUTH_SKIP)
	output := captureStdout(func() {
		err := (&ListSSORolesCmd{}).Run(ctx)
		require.NoError(t, err)
	})

	assert.Contains(t, output, "123456789012")
	assert.Contains(t, output, "ReadOnly")
	assert.Contains(t, output, "PowerUser")
}

// TestE2EListSSORolesEmpty verifies that an empty account list produces no error
// and no role rows.
func TestE2EListSSORolesEmpty(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)

	setup.Server.SSO.QueueListAccounts(awsmock.ListAccountsResponse{
		AccountList: []awsmock.AccountInfo{},
	})

	ctx := newRunContext(setup, AUTH_SKIP)
	output := captureStdout(func() {
		err := (&ListSSORolesCmd{}).Run(ctx)
		require.NoError(t, err)
	})

	assert.NotContains(t, output, "ReadOnly",
		"empty account list should produce no role rows")
}

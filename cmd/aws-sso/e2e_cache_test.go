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

// TestE2ECache verifies that CacheCmd.Run fetches accounts/roles from SSO and
// persists them to the local cache file.
func TestE2ECache(t *testing.T) {
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

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Cache = CacheCmd{Threads: 1, NoConfigCheck: true, Silent: true}

	output := captureStdout(func() {
		err := (&CacheCmd{}).Run(ctx)
		require.NoError(t, err)
	})

	// Verify the cache has the expected accounts and roles.
	ssoCache := setup.Settings.Cache.GetSSO()
	require.NotNil(t, ssoCache.Roles)
	allRoles := ssoCache.Roles.GetAllRoles()
	roleNames := make([]string, 0, len(allRoles))
	for _, r := range allRoles {
		roleNames = append(roleNames, r.RoleName)
	}
	assert.Contains(t, roleNames, "ReadOnly")
	assert.Contains(t, roleNames, "PowerUser")
	_ = output // output goes to stdout but we don't assert on its format
}

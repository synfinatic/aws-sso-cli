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
	ssoauth "github.com/synfinatic/aws-sso-cli/internal/sso/auth"
)

// TestE2ELogout_Run exercises LogoutCmd.Run when the store has no cached SSO token.
// In that case flushSts runs (no-op with empty cache) and Logout returns an error
// from the missing token — no real AWS network call is made.
func TestE2ELogout_Run(t *testing.T) {
	setup := newE2ESetup(t)
	// Intentionally do NOT call preAuth — store has no CreateTokenResponse.
	// LogoutCmd.Run still runs flushSts, then Logout fails with "no token" error.
	ctx := newRunContext(setup, AUTH_SKIP)
	err := (&LogoutCmd{}).Run(ctx)
	// The error comes from GetCreateTokenResponse returning "no token found".
	assert.Error(t, err)
}

// TestFlushSts_Empty verifies flushSts is a no-op on an empty (no roles) cache.
func TestFlushSts_Empty(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	// Do NOT call populateCache — cache has no roles.

	s, err := setup.Settings.GetSelectedSSO(setup.SSOName)
	require.NoError(t, err)
	awssso := ssoauth.NewAWSSSO(s, setup.Store)

	ctx := newRunContext(setup, AUTH_SKIP)
	// Should not panic or error even with an empty cache.
	assert.NotPanics(t, func() {
		flushSts(ctx, awssso)
	})
}

// TestFlushSts_WithRoles verifies flushSts marks all roles expired after clearing STS creds.
func TestFlushSts_WithRoles(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)

	s, err := setup.Settings.GetSelectedSSO(setup.SSOName)
	require.NoError(t, err)
	awssso := ssoauth.NewAWSSSO(s, setup.Store)

	ctx := newRunContext(setup, AUTH_SKIP)
	flushSts(ctx, awssso)

	ssoCache := setup.Settings.Cache.GetSSO()
	for _, role := range ssoCache.Roles.GetAllRoles() {
		assert.True(t, role.IsExpired(), "role %s should be expired after flushSts", role.Arn)
	}
}

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
)

// TestGetRoleCredentials_CacheMiss verifies that when no credentials exist in
// the cache or secure store, GetRoleCredentials fetches them from AWS SSO and
// persists them for future calls.
func TestGetRoleCredentials_CacheMiss(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	creds := GetRoleCredentials(ctx, AwsSSO, false, 123456789012, "ReadOnly")

	require.NotNil(t, creds)
	assert.Equal(t, "AKIDTEST12345", creds.AccessKeyId)
	assert.Equal(t, "SECRETTEST12345", creds.SecretAccessKey)
	assert.Equal(t, "TOKENTEST12345", creds.SessionToken)
}

// TestGetRoleCredentials_CacheHit verifies that a second call with no queued
// SSO response succeeds by reading credentials from the secure store/cache
// populated by the first call.
func TestGetRoleCredentials_CacheHit(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server) // consumed by the first (cold) call

	ctx := newRunContext(setup, AUTH_REQUIRED)

	// First call: cold path — fetches from SSO and populates store + cache expiry.
	first := GetRoleCredentials(ctx, AwsSSO, false, 123456789012, "ReadOnly")
	require.NotNil(t, first)

	// Second call: no response queued — must succeed from cache/store.
	second := GetRoleCredentials(ctx, AwsSSO, false, 123456789012, "ReadOnly")
	require.NotNil(t, second)
	assert.Equal(t, first.AccessKeyId, second.AccessKeyId)
	assert.Equal(t, first.SecretAccessKey, second.SecretAccessKey)
}

// TestGetRoleCredentials_ForceRefresh verifies that refreshSTS=true bypasses
// the cache and always fetches fresh credentials from AWS SSO.
func TestGetRoleCredentials_ForceRefresh(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server) // first fetch (cold)
	queueRoleCredentials(setup.Server) // second fetch (forced refresh)

	ctx := newRunContext(setup, AUTH_REQUIRED)

	// First call: populate cache and store.
	first := GetRoleCredentials(ctx, AwsSSO, false, 123456789012, "ReadOnly")
	require.NotNil(t, first)

	// Second call: force refresh must ignore the cached copy and consume the
	// second queued response.
	second := GetRoleCredentials(ctx, AwsSSO, true, 123456789012, "ReadOnly")
	require.NotNil(t, second)
	assert.Equal(t, "AKIDTEST12345", second.AccessKeyId)
}

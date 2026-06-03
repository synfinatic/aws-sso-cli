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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/synfinatic/aws-sso-cli/internal/ecs/server"
	"golang.org/x/net/nettest"
)

// TestE2EEcsServerDefault exercises the full `ecs server --default` path:
//  1. Populate the SSO cache with a test account and role via the mock AWS server.
//  2. Queue a GetRoleCredentials response so the mock returns predictable creds.
//  3. Call setServerDefaultProfile to resolve the profile and inject creds into
//     the server's default slot (the same code path as `ecs server --default`).
//  4. Start the ECS HTTP server and verify that:
//     - GET / returns the expected credentials.
//     - GET /healthcheck returns HTTP 200.
func TestE2EEcsServerDefault(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	l, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	s, err := server.NewEcsServer(context.Background(), "", l, "", "")
	require.NoError(t, err)
	t.Cleanup(s.Close)

	ctx := newRunContext(setup, AUTH_REQUIRED)

	// setServerDefaultProfile resolves the profile via the cache and injects credentials
	// into the server's default slot — this is the core of `ecs server --default`.
	err = setServerDefaultProfile(ctx, s, "123456789012:ReadOnly")
	require.NoError(t, err, "setServerDefaultProfile should succeed with a populated cache")

	assert.Equal(t, "123456789012:ReadOnly", s.DefaultCreds.ProfileName,
		"default slot profile name should match the requested profile")
	assert.Equal(t, "AKIDTEST12345", s.DefaultCreds.Creds.AccessKeyId,
		"default slot should hold the queued test access key")

	// Start the HTTP server in the background; Close() shuts it down on cleanup.
	go func() { _ = s.Serve() }()

	serverAddr := l.Addr().String()
	baseURL := fmt.Sprintf("http://%s", serverAddr)

	// Poll until the server is reachable (it may not be listening yet).
	require.NoError(t, waitForEcsServerUp("http", serverAddr, "", 5*time.Second),
		"ECS server should become reachable after Serve() is called")

	// GET / should return the pre-loaded credentials.
	resp, err := http.Get(baseURL + "/") // nolint:gosec,noctx
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"GET / should return 200 once default credentials are loaded")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var creds map[string]string
	require.NoError(t, json.Unmarshal(body, &creds), "response body should be valid JSON")
	assert.Equal(t, "AKIDTEST12345", creds["AccessKeyId"],
		"credential endpoint should return the queued access key ID")
	assert.Equal(t, "SECRETTEST12345", creds["SecretAccessKey"],
		"credential endpoint should return the queued secret access key")
	assert.Equal(t, "TOKENTEST12345", creds["Token"],
		"credential endpoint should return the queued session token")

	// GET /healthcheck should return 200 now that default credentials are loaded.
	hcResp, err := http.Get(baseURL + "/healthcheck") // nolint:gosec,noctx
	require.NoError(t, err)
	defer hcResp.Body.Close()
	assert.Equal(t, http.StatusOK, hcResp.StatusCode,
		"healthcheck should return 200 after default credentials are loaded")
}

// TestE2EEcsDockerStartDefault exercises the `ecs docker start --default` sequence
// without requiring a real Docker daemon. It validates the three-step handshake
// that the docker start command performs after the container is running:
//
//  1. waitForEcsServerUp — succeeds as soon as the server responds (even 503).
//  2. loadProfileToEcsServer — resolves the profile and PUTs credentials via HTTP.
//  3. waitForEcsHealthcheck — polls until GET /healthcheck returns 200.
//
// This proves the full post-container-start flow works end-to-end.
func TestE2EEcsDockerStartDefault(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	l, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	// No auth and no SSL — mirrors what a simple `ecs docker start` uses in a
	// test environment where auth/TLS are not configured.
	s, err := server.NewEcsServer(context.Background(), "", l, "", "")
	require.NoError(t, err)
	t.Cleanup(s.Close)

	go func() { _ = s.Serve() }()

	serverAddr := l.Addr().String()

	// Step 1: wait until the server is up (any HTTP response, including 503).
	err = waitForEcsServerUp("http", serverAddr, "", 5*time.Second)
	require.NoError(t, err, "waitForEcsServerUp should succeed once the server is listening")

	// Healthcheck should be 503 before any credentials are loaded.
	hcURL := fmt.Sprintf("http://%s/healthcheck", serverAddr)
	hcResp, err := http.Get(hcURL) // nolint:gosec,noctx
	require.NoError(t, err)
	hcResp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, hcResp.StatusCode,
		"healthcheck should be 503 before default credentials are loaded")

	// Step 2: resolve the profile and PUT credentials into the running server.
	ctx := newRunContext(setup, AUTH_REQUIRED)
	err = loadProfileToEcsServer(ctx, "123456789012:ReadOnly", serverAddr)
	require.NoError(t, err, "loadProfileToEcsServer should succeed with a populated cache")

	// Step 3: healthcheck should now return 200.
	err = waitForEcsHealthcheck("http", serverAddr, "", 5*time.Second)
	require.NoError(t, err, "waitForEcsHealthcheck should return 200 after credentials are loaded")

	// Verify the credentials are actually served correctly via GET /.
	resp, err := http.Get(fmt.Sprintf("http://%s/", serverAddr)) // nolint:gosec,noctx
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var creds map[string]string
	require.NoError(t, json.Unmarshal(body, &creds))
	assert.Equal(t, "AKIDTEST12345", creds["AccessKeyId"])
	assert.Equal(t, "SECRETTEST12345", creds["SecretAccessKey"])
	assert.Equal(t, "TOKENTEST12345", creds["Token"])
}

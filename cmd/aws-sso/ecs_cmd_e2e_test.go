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
	"net"
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

// freePort returns a TCP port number that was free at the time of the call.  There
// is a brief TOCTOU window between Close() and the caller's Listen(), which is
// acceptable for tests running on loopback.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// newEcsServerForTest starts an in-process ECS server on a random port and returns
// the server and its host:port address.  The server is closed via t.Cleanup.
func newEcsServerForTest(t *testing.T) (*server.EcsServer, string) {
	t.Helper()
	l, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)
	s, err := server.NewEcsServer(context.Background(), "", l, "", "")
	require.NoError(t, err)
	t.Cleanup(s.Close)
	go func() { _ = s.Serve() }()
	addr := l.Addr().String()
	require.NoError(t, waitForEcsServerUp("http", addr, "", 5*time.Second))
	return s, addr
}

// TestE2EEcsLoad exercises the `ecs load` path for the default slot:
//  1. Populate the SSO cache and queue a GetRoleCredentials response.
//  2. Call ecsLoadCmd to PUT credentials into the running server.
//  3. Verify GET / returns the expected credentials.
func TestE2EEcsLoad(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	_, addr := newEcsServerForTest(t)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Ecs.Load.Server = addr

	err := ecsLoadCmd(ctx, 123456789012, "ReadOnly")
	require.NoError(t, err)

	resp, err := http.Get(fmt.Sprintf("http://%s/", addr)) // nolint:gosec,noctx
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var got map[string]string
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, "AKIDTEST12345", got["AccessKeyId"])
	assert.Equal(t, "SECRETTEST12345", got["SecretAccessKey"])
	assert.Equal(t, "TOKENTEST12345", got["Token"])
}

// TestE2EEcsLoadSlotted exercises the `ecs load --slotted` path:
//  1. Populate the SSO cache and queue a GetRoleCredentials response.
//  2. Call ecsLoadCmd with Slotted=true to PUT credentials into a named slot.
//  3. Verify the slot healthcheck returns 200.
func TestE2EEcsLoadSlotted(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	_, addr := newEcsServerForTest(t)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Ecs.Load.Server = addr
	ctx.Cli.Ecs.Load.Slotted = true

	err := ecsLoadCmd(ctx, 123456789012, "ReadOnly")
	require.NoError(t, err)

	// Default slot should still be empty (503).
	hcResp, err := http.Get(fmt.Sprintf("http://%s/healthcheck", addr)) // nolint:gosec,noctx
	require.NoError(t, err)
	hcResp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, hcResp.StatusCode,
		"default slot should remain empty when loading into a named slot")

	// Named-slot healthcheck should return 200.
	slotHC := fmt.Sprintf("http://%s/healthcheck/slot/123456789012:ReadOnly", addr)
	slotResp, err := http.Get(slotHC) // nolint:gosec,noctx
	require.NoError(t, err)
	slotResp.Body.Close()
	assert.Equal(t, http.StatusOK, slotResp.StatusCode,
		"named-slot healthcheck should return 200 after slotted load")
}

// TestE2EEcsProfile exercises the `ecs profile` path:
//  1. Load credentials into the default slot via setServerDefaultProfile.
//  2. Call EcsProfileCmd.Run and capture stdout.
//  3. Verify the output contains the account ID and role name.
func TestE2EEcsProfile(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	s, addr := newEcsServerForTest(t)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	err := setServerDefaultProfile(ctx, s, "123456789012:ReadOnly")
	require.NoError(t, err)

	ctx.Cli.Ecs.Profile.Server = addr
	output := captureStdout(func() {
		runErr := (&EcsProfileCmd{}).Run(ctx)
		assert.NoError(t, runErr)
	})
	assert.Contains(t, output, "123456789012", "profile output should include the account ID")
	assert.Contains(t, output, "ReadOnly", "profile output should include the role name")
}

// TestE2EEcsList exercises the `ecs list` path:
//  1. Load a credential into a named slot via ecsLoadCmd with Slotted=true.
//  2. Call EcsListCmd.Run and capture stdout.
//  3. Verify the output contains the account ID and role name.
func TestE2EEcsList(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	_, addr := newEcsServerForTest(t)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Ecs.Load.Server = addr
	ctx.Cli.Ecs.Load.Slotted = true
	err := ecsLoadCmd(ctx, 123456789012, "ReadOnly")
	require.NoError(t, err)

	ctx.Cli.Ecs.List.Server = addr
	output := captureStdout(func() {
		runErr := (&EcsListCmd{}).Run(ctx)
		assert.NoError(t, runErr)
	})
	assert.Contains(t, output, "123456789012", "list output should include the account ID")
	assert.Contains(t, output, "ReadOnly", "list output should include the role name")
}

// TestE2EEcsUnload exercises the `ecs unload` path for the default slot:
//  1. Load credentials into the default slot.
//  2. Confirm the healthcheck returns 200.
//  3. Call EcsUnloadCmd.Run with no profile (default slot).
//  4. Verify the healthcheck now returns 503.
func TestE2EEcsUnload(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	s, addr := newEcsServerForTest(t)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	err := setServerDefaultProfile(ctx, s, "123456789012:ReadOnly")
	require.NoError(t, err)

	hcResp, err := http.Get(fmt.Sprintf("http://%s/healthcheck", addr)) // nolint:gosec,noctx
	require.NoError(t, err)
	hcResp.Body.Close()
	require.Equal(t, http.StatusOK, hcResp.StatusCode, "healthcheck should be 200 before unload")

	ctx.Cli.Ecs.Unload.Server = addr
	ctx.Cli.Ecs.Unload.Profile = ""
	err = (&EcsUnloadCmd{}).Run(ctx)
	require.NoError(t, err)

	hcResp2, err := http.Get(fmt.Sprintf("http://%s/healthcheck", addr)) // nolint:gosec,noctx
	require.NoError(t, err)
	hcResp2.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, hcResp2.StatusCode,
		"healthcheck should return 503 after unloading the default slot")
}

// TestE2EEcsUnloadSlotted exercises the `ecs unload --profile` path for a named slot:
//  1. Load a credential into a named slot.
//  2. Confirm the slot healthcheck returns 200.
//  3. Call EcsUnloadCmd.Run with the profile name.
//  4. Verify the slot healthcheck now returns 503.
func TestE2EEcsUnloadSlotted(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	_, addr := newEcsServerForTest(t)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Ecs.Load.Server = addr
	ctx.Cli.Ecs.Load.Slotted = true
	err := ecsLoadCmd(ctx, 123456789012, "ReadOnly")
	require.NoError(t, err)

	slotHC := fmt.Sprintf("http://%s/healthcheck/slot/123456789012:ReadOnly", addr)
	hcResp, err := http.Get(slotHC) // nolint:gosec,noctx
	require.NoError(t, err)
	hcResp.Body.Close()
	require.Equal(t, http.StatusOK, hcResp.StatusCode, "slot healthcheck should be 200 before unload")

	ctx.Cli.Ecs.Unload.Server = addr
	ctx.Cli.Ecs.Unload.Profile = "123456789012:ReadOnly"
	err = (&EcsUnloadCmd{}).Run(ctx)
	require.NoError(t, err)

	hcResp2, err := http.Get(slotHC) // nolint:gosec,noctx
	require.NoError(t, err)
	hcResp2.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, hcResp2.StatusCode,
		"slot healthcheck should return 503 after unloading the named slot")
}

// TestE2EEcsServerRun exercises EcsServerCmd.Run() end-to-end without a default
// profile (no credentials pre-loaded).  The server starts, accepts connections,
// and shuts down cleanly when the context is cancelled.
func TestE2EEcsServerRun(t *testing.T) {
	setup := newE2ESetup(t)

	cctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	port := freePort(t)
	ctx := &RunContext{
		Cli:      &CLI{},
		Settings: setup.Settings,
		Store:    setup.Store,
		Auth:     AUTH_SKIP,
		Ctx:      cctx,
	}
	ctx.Cli.Ecs.Server = EcsServerCmd{
		BindIP:      "127.0.0.1",
		Port:        port,
		DisableAuth: true,
		DisableSSL:  true,
	}
	cc := &ctx.Cli.Ecs.Server

	done := make(chan error, 1)
	go func() { done <- cc.Run(ctx) }()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	require.NoError(t, waitForEcsServerUp("http", addr, "", 5*time.Second))

	// No credentials loaded → healthcheck returns 503.
	hcResp, err := http.Get(fmt.Sprintf("http://%s/healthcheck", addr)) // nolint:gosec,noctx
	require.NoError(t, err)
	hcResp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, hcResp.StatusCode,
		"healthcheck should be 503 when no credentials are loaded")

	cancel()
	assert.NoError(t, <-done, "Run() should return nil on context cancellation")
}

// TestE2EEcsServerRunWithDefault exercises EcsServerCmd.Run() with --default:
// credentials are injected into the default slot before Serve() starts, so
// the healthcheck immediately returns 200 and GET / returns the test credentials.
func TestE2EEcsServerRunWithDefault(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	cctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	port := freePort(t)
	ctx := &RunContext{
		Cli:      &CLI{},
		Settings: setup.Settings,
		Store:    setup.Store,
		Auth:     AUTH_REQUIRED,
		Ctx:      cctx,
	}
	ctx.Cli.Ecs.Server = EcsServerCmd{
		BindIP:      "127.0.0.1",
		Port:        port,
		DisableAuth: true,
		DisableSSL:  true,
		Default:     "123456789012:ReadOnly",
	}
	cc := &ctx.Cli.Ecs.Server

	done := make(chan error, 1)
	go func() { done <- cc.Run(ctx) }()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	require.NoError(t, waitForEcsServerUp("http", addr, "", 5*time.Second))

	// Default credentials loaded before Serve() → healthcheck should be 200.
	hcResp, err := http.Get(fmt.Sprintf("http://%s/healthcheck", addr)) // nolint:gosec,noctx
	require.NoError(t, err)
	hcResp.Body.Close()
	assert.Equal(t, http.StatusOK, hcResp.StatusCode,
		"healthcheck should be 200 after --default credentials are loaded")

	// GET / should return the test credentials.
	resp, err := http.Get(fmt.Sprintf("http://%s/", addr)) // nolint:gosec,noctx
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

	cancel()
	assert.NoError(t, <-done, "Run() should return nil on context cancellation")
}

// TestE2EEcsServerRunWithAuth exercises bearer-token enforcement in EcsServerCmd.Run():
//   - A token saved in the store is applied to all non-healthcheck routes.
//   - Requests without the Authorization header receive 403 Forbidden.
//   - Requests with the correct Bearer token reach the credential handler.
//   - The /healthcheck route bypasses auth and always responds.
func TestE2EEcsServerRunWithAuth(t *testing.T) {
	setup := newE2ESetup(t)

	const token = "test-bearer-token"
	require.NoError(t, setup.Store.SaveEcsBearerToken(context.Background(), token))

	cctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	port := freePort(t)
	ctx := &RunContext{
		Cli:      &CLI{},
		Settings: setup.Settings,
		Store:    setup.Store,
		Auth:     AUTH_SKIP,
		Ctx:      cctx,
	}
	ctx.Cli.Ecs.Server = EcsServerCmd{
		BindIP:     "127.0.0.1",
		Port:       port,
		DisableSSL: true,
		// DisableAuth is false: bearer token from store will be enforced.
	}
	cc := &ctx.Cli.Ecs.Server

	done := make(chan error, 1)
	go func() { done <- cc.Run(ctx) }()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	require.NoError(t, waitForEcsServerUp("http", addr, "", 5*time.Second))

	// /healthcheck bypasses auth → should respond even without a token.
	hcResp, err := http.Get(fmt.Sprintf("http://%s/healthcheck", addr)) // nolint:gosec,noctx
	require.NoError(t, err)
	hcResp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, hcResp.StatusCode,
		"healthcheck should return 503 (no creds) without needing auth")

	// GET / without Authorization header → 403 Forbidden.
	unauthResp, err := http.Get(fmt.Sprintf("http://%s/", addr)) // nolint:gosec,noctx
	require.NoError(t, err)
	unauthResp.Body.Close()
	assert.Equal(t, http.StatusForbidden, unauthResp.StatusCode,
		"unauthenticated request should be rejected with 403")

	// GET / with correct Bearer token → reaches the credential handler (404: no creds loaded).
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, fmt.Sprintf("http://%s/", addr), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	authResp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	authResp.Body.Close()
	assert.Equal(t, http.StatusNotFound, authResp.StatusCode,
		"authenticated request should reach the credential handler (404: no creds loaded)")

	cancel()
	assert.NoError(t, <-done, "Run() should return nil on context cancellation")
}

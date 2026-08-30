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
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/synfinatic/aws-sso-cli/internal/certutil"
	ecsclient "github.com/synfinatic/aws-sso-cli/internal/ecs/client"
)

// TestE2ESetupEcsSSL exercises the basic CA lifecycle of the `setup ecs ssl`
// command:
//  1. Generate a CA (--self-signed).
//  2. Delete the stored CA (--delete) and confirm the store is empty.
func TestE2ESetupEcsSSL(t *testing.T) {
	isolateHomeForCaExport(t)

	setup := newE2ESetup(t)
	ctx := newRunContext(setup, AUTH_SKIP)

	// --- Generate: --self-signed ---
	ctx.Cli.Setup.Ecs.SSL = EcsSSLCmd{SelfSigned: true}
	require.NoError(t, (&EcsSSLCmd{}).Run(ctx), "setup ecs ssl --self-signed should store a CA")

	storedCert, err := setup.Store.GetEcsCaCert()
	require.NoError(t, err)
	assert.NotEmpty(t, storedCert, "stored CA cert should be populated")

	// --- Delete: --delete ---
	ctx.Cli.Setup.Ecs.SSL = EcsSSLCmd{Delete: true}
	require.NoError(t, (&EcsSSLCmd{}).Run(ctx))

	afterCert, err := setup.Store.GetEcsCaCert()
	require.NoError(t, err)
	assert.Empty(t, afterCert, "CA cert should be cleared from store after --delete")
}

// TestE2EEcsServerSSL proves the full SSL/TLS path end-to-end:
//  1. Generate a CA and store it directly (bypassing the `setup ecs ssl`
//     command -- this test cares about EcsServerCmd.Run()'s leaf-minting and
//     ServeTLS wiring, not the `setup` command itself).
//  2. Start EcsServerCmd.Run() without DisableSSL -- it mints a fresh leaf
//     from the stored CA and passes it to server.Serve() -> ServeTLS.
//  3. Poll with waitForEcsServerUp using "https" and the CA cert: this fails
//     unless the server is actually serving TLS with a leaf that chains to
//     the CA (a plain-HTTP server, or one presenting an unrelated cert,
//     would cause TLS handshake errors and the poll would time out).
//  4. Make an explicit HTTPS GET /healthcheck with a CA-trusting TLS client
//     to confirm the minted certificate is correctly presented and trusted.
//  5. Cancel the context and verify Run() returns nil.
func TestE2EEcsServerSSL(t *testing.T) {
	setup := newE2ESetup(t)
	ctx := newRunContext(setup, AUTH_SKIP)

	ca, err := certutil.GenerateCA()
	require.NoError(t, err)
	require.NoError(t, setup.Store.SaveEcsCaKeyPair(ctx.Ctx, []byte(ca.KeyPEM), []byte(ca.CertPEM)))

	// Start the ECS server with TLS enabled.
	cctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ctx.Ctx = cctx

	port := freePort(t)
	ctx.Cli.Ecs.Server = EcsServerCmd{
		BindIP:      "127.0.0.1",
		Port:        port,
		DisableAuth: true,
		// DisableSSL defaults to false — Run() mints a fresh leaf from the stored CA and calls ServeTLS.
	}
	cc := &ctx.Cli.Ecs.Server

	done := make(chan error, 1)
	go func() { done <- cc.Run(ctx) }()

	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// waitForEcsServerUp with "https" builds a TLS client that trusts the CA,
	// not any particular leaf. If the server were serving plain HTTP, or a
	// leaf that doesn't chain to this CA, this would always fail.
	require.NoError(t, waitForEcsServerUp("https", addr, ca.CertPEM, 5*time.Second),
		"HTTPS ECS server should become reachable once ServeTLS is active with a CA-issued leaf")

	// Confirm the minted certificate is correctly presented by making a
	// direct HTTPS request through a client that trusts only the CA.
	tlsClient, err := ecsclient.NewHTTPClient(ca.CertPEM)
	require.NoError(t, err)
	tlsClient.Timeout = 5 * time.Second

	hcResp, err := tlsClient.Get(fmt.Sprintf("https://%s/healthcheck", addr)) // nolint:gosec,noctx
	require.NoError(t, err)
	hcResp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, hcResp.StatusCode,
		"HTTPS healthcheck should return 503 when no credentials are loaded")

	cancel()
	assert.NoError(t, <-done, "Run() should return nil on context cancellation")
}

// isolateHomeForCaExport points $HOME at a fresh temp dir so printCaAndInstructions's
// write of the CA export (under config.ConfigDir()) never touches the real user's
// home directory, while pre-creating ~/.config/aws-sso so the SecureStore's flock
// file (also derived from config.ConfigDir(), independently of where the JSON store
// file itself lives) can still be created.
func isolateHomeForCaExport(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".config", "aws-sso"), 0700))
	t.Setenv("HOME", home)
	return home
}

// TestE2ESetupEcsSSL_SelfSigned exercises the full `setup ecs ssl --self-signed`
// lifecycle: generate, rerun (CA reused byte-for-byte), --print-ca, and --delete.
func TestE2ESetupEcsSSL_SelfSigned(t *testing.T) {
	isolateHomeForCaExport(t)

	setup := newE2ESetup(t)
	ctx := newRunContext(setup, AUTH_SKIP)

	// --- Generate: --self-signed ---
	ctx.Cli.Setup.Ecs.SSL = EcsSSLCmd{SelfSigned: true}
	require.NoError(t, (&EcsSSLCmd{}).Run(ctx))

	caCert1, err := setup.Store.GetEcsCaCert()
	require.NoError(t, err)
	assert.NotEmpty(t, caCert1)

	// --- Rerun: CA is reused byte-for-byte ---
	ctx.Cli.Setup.Ecs.SSL = EcsSSLCmd{SelfSigned: true}
	require.NoError(t, (&EcsSSLCmd{}).Run(ctx))

	caCert2, err := setup.Store.GetEcsCaCert()
	require.NoError(t, err)
	assert.Equal(t, caCert1, caCert2, "rerunning --self-signed must not rotate the CA")

	// --- Print CA: --print-ca ---
	ctx.Cli.Setup.Ecs.SSL = EcsSSLCmd{PrintCa: true}
	output := captureStdout(func() {
		assert.NoError(t, (&EcsSSLCmd{}).Run(ctx))
	})
	assert.Contains(t, output, caCert2, "--print-ca should print the CA certificate PEM")
	assert.Contains(t, output, "SHA-256 fingerprint:",
		"--print-ca should not error and should print trust instructions")
	assert.Contains(t, output, ecsSslTrustDocsURL,
		"--print-ca output should link to the full trust instructions in the docs")

	// --- Delete: --delete clears the CA ---
	ctx.Cli.Setup.Ecs.SSL = EcsSSLCmd{Delete: true}
	require.NoError(t, (&EcsSSLCmd{}).Run(ctx))

	afterCA, err := setup.Store.GetEcsCaCert()
	require.NoError(t, err)
	assert.Empty(t, afterCA)
}

// TestE2EEcsServerSSL_SelfSigned_ChainOfTrust proves real chain-of-trust (not
// exact-leaf-pinning): a client that trusts only the CA — never the leaf directly —
// can complete a TLS handshake against the running ECS Server, and a client that
// trusts an unrelated CA cannot.
func TestE2EEcsServerSSL_SelfSigned_ChainOfTrust(t *testing.T) {
	isolateHomeForCaExport(t)

	setup := newE2ESetup(t)
	ctx := newRunContext(setup, AUTH_SKIP)

	ctx.Cli.Setup.Ecs.SSL = EcsSSLCmd{SelfSigned: true}
	require.NoError(t, (&EcsSSLCmd{}).Run(ctx))

	caCertPEM, err := setup.Store.GetEcsCaCert()
	require.NoError(t, err)
	require.NotEmpty(t, caCertPEM)

	// Start the ECS server with TLS enabled; it mints its own leaf from the
	// stored CA at startup.
	cctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ctx.Ctx = cctx

	port := freePort(t)
	ctx.Cli.Ecs.Server = EcsServerCmd{
		BindIP:      "127.0.0.1",
		Port:        port,
		DisableAuth: true,
	}
	cc := &ctx.Cli.Ecs.Server

	done := make(chan error, 1)
	go func() { done <- cc.Run(ctx) }()

	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// Trusting only the CA (not the leaf) proves the leaf actually chains to it.
	require.NoError(t, waitForEcsServerUp("https", addr, caCertPEM, 5*time.Second),
		"HTTPS ECS server should be reachable by a client that trusts only the CA")

	tlsClient, err := ecsclient.NewHTTPClient(caCertPEM)
	require.NoError(t, err)
	tlsClient.Timeout = 5 * time.Second

	hcResp, err := tlsClient.Get(fmt.Sprintf("https://%s/healthcheck", addr)) // nolint:gosec,noctx
	require.NoError(t, err)
	hcResp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, hcResp.StatusCode,
		"HTTPS healthcheck should return 503 when no credentials are loaded")

	// Negative case: a client trusting an unrelated CA must fail the handshake.
	unrelatedCA, err := certutil.GenerateCA()
	require.NoError(t, err)
	unrelatedClient, err := ecsclient.NewHTTPClient(unrelatedCA.CertPEM)
	require.NoError(t, err)
	unrelatedClient.Timeout = 5 * time.Second

	_, err = unrelatedClient.Get(fmt.Sprintf("https://%s/healthcheck", addr)) // nolint:gosec,noctx
	assert.Error(t, err, "a client trusting an unrelated CA must fail the TLS handshake")

	cancel()
	assert.NoError(t, <-done, "Run() should return nil on context cancellation")
}

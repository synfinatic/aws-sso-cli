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

// isolateHomeForCaExport points $HOME at a fresh temp dir so these tests never
// touch the real user's home directory, while pre-creating ~/.config/aws-sso so
// the SecureStore's flock file (derived from config.ConfigDir(), which resolves
// against $HOME independently of where the JSON store file itself lives) can
// still be created.
func isolateHomeForCaExport(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".config", "aws-sso"), 0700))
	t.Setenv("HOME", home)
	return home
}

// TestE2ESetupEcsSSL_SelfSigned exercises the full `setup ecs ssl --self-signed`
// lifecycle: generate, rerun (CA reused, leaf rotates), --print-ca, --delete
// (leaf only), and --delete-ca (leaf must already be gone).
func TestE2ESetupEcsSSL_SelfSigned(t *testing.T) {
	isolateHomeForCaExport(t)

	setup := newE2ESetup(t)
	ctx := newRunContext(setup, AUTH_SKIP)

	// --- Generate: --self-signed ---
	require.NoError(t, (&EcsSSLCmd{SelfSigned: true}).Run(ctx))

	caCert1, err := setup.Store.GetEcsCaCert()
	require.NoError(t, err)
	assert.NotEmpty(t, caCert1)
	leafCert1, err := setup.Store.GetEcsSslCert()
	require.NoError(t, err)
	assert.NotEmpty(t, leafCert1)

	// --- Rerun: CA is reused byte-for-byte, leaf rotates ---
	require.NoError(t, (&EcsSSLCmd{SelfSigned: true}).Run(ctx))

	caCert2, err := setup.Store.GetEcsCaCert()
	require.NoError(t, err)
	leafCert2, err := setup.Store.GetEcsSslCert()
	require.NoError(t, err)
	assert.Equal(t, caCert1, caCert2, "rerunning --self-signed must not rotate the CA")
	assert.NotEqual(t, leafCert1, leafCert2, "rerunning --self-signed should rotate the leaf")

	// --- Print CA: --print-ca ---
	caOutput := captureStdout(func() {
		assert.NoError(t, (&EcsSSLCmd{PrintCa: true}).Run(ctx))
	})
	assert.Contains(t, caOutput, "BEGIN CERTIFICATE",
		"--print-ca should output the CA's PEM certificate block")
	assert.Equal(t, caCert2, caOutput,
		"--print-ca should print the CA certificate PEM and nothing else, not even a trailing newline")

	// --- Delete: --delete clears only the leaf, CA stays intact ---
	require.NoError(t, (&EcsSSLCmd{Delete: true}).Run(ctx))

	afterDeleteCA, err := setup.Store.GetEcsCaCert()
	require.NoError(t, err)
	assert.NotEmpty(t, afterDeleteCA, "--delete must not remove the CA")

	afterDeleteLeaf, err := setup.Store.GetEcsSslCert()
	require.NoError(t, err)
	assert.Empty(t, afterDeleteLeaf)

	// --- Delete CA: --delete-ca now succeeds since the leaf is already gone ---
	require.NoError(t, (&EcsSSLCmd{DeleteCa: true}).Run(ctx))

	afterDeleteCaCA, err := setup.Store.GetEcsCaCert()
	require.NoError(t, err)
	assert.Empty(t, afterDeleteCaCA)
}

// TestE2EEcsServerSSL_SelfSigned_ChainOfTrust proves real chain-of-trust (not
// exact-leaf-pinning): a client that trusts only the CA — never the leaf directly —
// can complete a TLS handshake against the running ECS Server, and a client that
// trusts an unrelated CA cannot.
func TestE2EEcsServerSSL_SelfSigned_ChainOfTrust(t *testing.T) {
	isolateHomeForCaExport(t)

	setup := newE2ESetup(t)
	ctx := newRunContext(setup, AUTH_SKIP)

	require.NoError(t, (&EcsSSLCmd{SelfSigned: true}).Run(ctx))

	caCertPEM, err := setup.Store.GetEcsCaCert()
	require.NoError(t, err)
	require.NotEmpty(t, caCertPEM)

	// Start the ECS server with TLS enabled using the self-signed leaf.
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

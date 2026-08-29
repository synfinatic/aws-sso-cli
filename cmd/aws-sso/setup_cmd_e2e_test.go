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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
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

// generateSelfSignedCert creates an ECDSA P-256 self-signed certificate valid
// for 127.0.0.1 / localhost.  Both PEM strings are returned.
func generateSelfSignedCert(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

	// SaveEcsSslKeyPair validates with x509.ParsePKCS8PrivateKey, so we must use
	// PKCS#8 marshalling ("PRIVATE KEY" PEM type), not the SEC 1 EC form.
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return
}

// TestE2ESetupEcsSSL exercises the leaf-cert operations of the `setup ecs ssl`
// command:
//  1. Generate a leaf certificate (--self-signed, the only generation path now
//     that the BYO-certificate --certificate/--private-key flags are gone).
//  2. Print the stored certificate (--print) and confirm the output.
//  3. Delete the stored pair (--delete) and confirm the store is empty.
func TestE2ESetupEcsSSL(t *testing.T) {
	isolateHomeForCaExport(t)

	setup := newE2ESetup(t)
	ctx := newRunContext(setup, AUTH_SKIP)

	// --- Generate: --self-signed ---
	ctx.Cli.Setup.Ecs.SSL = EcsSSLCmd{SelfSigned: true}
	require.NoError(t, (&EcsSSLCmd{}).Run(ctx), "setup ecs ssl --self-signed should store a leaf cert+key")

	storedCert, err := setup.Store.GetEcsSslCert()
	require.NoError(t, err)
	assert.NotEmpty(t, storedCert, "stored cert should be populated")

	storedKey, err := setup.Store.GetEcsSslKey()
	require.NoError(t, err)
	assert.NotEmpty(t, storedKey, "stored key should be populated")

	// --- Print: --print ---
	ctx.Cli.Setup.Ecs.SSL = EcsSSLCmd{Print: true}
	output := captureStdout(func() {
		assert.NoError(t, (&EcsSSLCmd{}).Run(ctx))
	})
	assert.Contains(t, output, "BEGIN CERTIFICATE",
		"--print should output the PEM certificate block")

	// --- Delete: --delete ---
	ctx.Cli.Setup.Ecs.SSL = EcsSSLCmd{Delete: true}
	require.NoError(t, (&EcsSSLCmd{}).Run(ctx))

	afterCert, err := setup.Store.GetEcsSslCert()
	require.NoError(t, err)
	assert.Empty(t, afterCert, "cert should be cleared from store after --delete")

	afterKey, err := setup.Store.GetEcsSslKey()
	require.NoError(t, err)
	assert.Empty(t, afterKey, "key should be cleared from store after --delete")
}

// TestE2EEcsServerSSL proves the full SSL/TLS path end-to-end:
//  1. Generate a self-signed cert+key and store it directly (bypassing the
//     `setup ecs ssl` command, which now only ever issues certs via its own
//     internal/certutil CA — this test cares about EcsServerCmd.Run()'s
//     ServeTLS wiring, not certificate generation).
//  2. Start EcsServerCmd.Run() without DisableSSL — it reads the pair from the
//     store and passes them to server.Serve() → ServeTLS.
//  3. Poll with waitForEcsServerUp using "https" and the cert chain: this fails
//     unless the server is actually serving TLS (a plain-HTTP server would cause
//     TLS handshake errors and the poll would time out).
//  4. Make an explicit HTTPS GET /healthcheck with a custom TLS client to confirm
//     the certificate is correctly presented and trusted.
//  5. Cancel the context and verify Run() returns nil.
func TestE2EEcsServerSSL(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t)

	setup := newE2ESetup(t)
	ctx := newRunContext(setup, AUTH_SKIP)

	require.NoError(t, setup.Store.SaveEcsSslKeyPair(ctx.Ctx, []byte(keyPEM), []byte(certPEM)))

	// Start the ECS server with TLS enabled.
	cctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ctx.Ctx = cctx

	port := freePort(t)
	ctx.Cli.Ecs.Server = EcsServerCmd{
		BindIP:      "127.0.0.1",
		Port:        port,
		DisableAuth: true,
		// DisableSSL defaults to false — Run() reads the stored cert+key and calls ServeTLS.
	}
	cc := &ctx.Cli.Ecs.Server

	done := make(chan error, 1)
	go func() { done <- cc.Run(ctx) }()

	addr := fmt.Sprintf("127.0.0.1:%d", port)

	// waitForEcsServerUp with "https" builds a TLS client that trusts certPEM.
	// If the server were serving plain HTTP this would always fail (TLS error),
	// proving that TLS must be active for the poll to succeed.
	require.NoError(t, waitForEcsServerUp("https", addr, certPEM, 5*time.Second),
		"HTTPS ECS server should become reachable once ServeTLS is active")

	// Confirm the certificate is correctly presented by making a direct HTTPS request.
	tlsClient, err := ecsclient.NewHTTPClient(certPEM)
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
// lifecycle: generate, rerun (CA reused, leaf rotates), --print-ca, and --delete.
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
	leafCert1, err := setup.Store.GetEcsSslCert()
	require.NoError(t, err)
	assert.NotEmpty(t, leafCert1)

	// --- Rerun: CA is reused byte-for-byte, leaf rotates ---
	ctx.Cli.Setup.Ecs.SSL = EcsSSLCmd{SelfSigned: true}
	require.NoError(t, (&EcsSSLCmd{}).Run(ctx))

	caCert2, err := setup.Store.GetEcsCaCert()
	require.NoError(t, err)
	leafCert2, err := setup.Store.GetEcsSslCert()
	require.NoError(t, err)
	assert.Equal(t, caCert1, caCert2, "rerunning --self-signed must not rotate the CA")
	assert.NotEqual(t, leafCert1, leafCert2, "rerunning --self-signed should rotate the leaf")

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

	// --- Delete: --delete clears both CA and leaf ---
	ctx.Cli.Setup.Ecs.SSL = EcsSSLCmd{Delete: true}
	require.NoError(t, (&EcsSSLCmd{}).Run(ctx))

	afterCA, err := setup.Store.GetEcsCaCert()
	require.NoError(t, err)
	assert.Empty(t, afterCA)

	afterLeaf, err := setup.Store.GetEcsSslCert()
	require.NoError(t, err)
	assert.Empty(t, afterLeaf)
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

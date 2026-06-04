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

// TestE2ESetupEcsSSL exercises all three operations of the `setup ecs ssl` command:
//  1. Save a cert+key from PEM files (--certificate, --private-key, --force).
//  2. Print the stored certificate (--print) and confirm the output.
//  3. Delete the stored pair (--delete) and confirm the store is empty.
func TestE2ESetupEcsSSL(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t)

	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "cert.pem")
	keyFile := filepath.Join(tempDir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, []byte(certPEM), 0600))
	require.NoError(t, os.WriteFile(keyFile, []byte(keyPEM), 0600))

	setup := newE2ESetup(t)
	ctx := newRunContext(setup, AUTH_SKIP)

	// --- Save: --certificate, --private-key, --force ---
	ctx.Cli.Setup.Ecs.SSL = EcsSSLCmd{
		Certificate: certFile,
		PrivateKey:  keyFile,
		Force:       true,
	}
	require.NoError(t, (&EcsSSLCmd{}).Run(ctx), "setup ecs ssl should store the cert+key")

	storedCert, err := setup.Store.GetEcsSslCert()
	require.NoError(t, err)
	assert.Equal(t, certPEM, storedCert, "stored cert should match the PEM file content")

	storedKey, err := setup.Store.GetEcsSslKey()
	require.NoError(t, err)
	assert.Equal(t, keyPEM, storedKey, "stored key should match the PEM file content")

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
//  1. Generate a self-signed cert+key and store it via `setup ecs ssl --force`.
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

	tempDir := t.TempDir()
	certFile := filepath.Join(tempDir, "cert.pem")
	keyFile := filepath.Join(tempDir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, []byte(certPEM), 0600))
	require.NoError(t, os.WriteFile(keyFile, []byte(keyPEM), 0600))

	setup := newE2ESetup(t)
	ctx := newRunContext(setup, AUTH_SKIP)

	// Store cert+key so EcsServerCmd.Run() can read them.
	ctx.Cli.Setup.Ecs.SSL = EcsSSLCmd{
		Certificate: certFile,
		PrivateKey:  keyFile,
		Force:       true,
	}
	require.NoError(t, (&EcsSSLCmd{}).Run(ctx))

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

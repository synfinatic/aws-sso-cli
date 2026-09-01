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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/synfinatic/aws-sso-cli/internal/certutil"
	ssocache "github.com/synfinatic/aws-sso-cli/internal/sso/cache"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	testlogger "github.com/synfinatic/flexlog/test"
)

// freeTestPort returns a currently-unused TCP port on 127.0.0.1 for tests
// that need to bind their own listener (EcsServerCmd.Run picks its own
// net.Listen, so tests can't use port 0 directly).
func freeTestPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// TestEcsServerCmdRun_NativeMintsLeafFromCA proves the native (non-Docker)
// path mints a fresh leaf from the stored CA rather than reading a
// persisted leaf: a client trusting only the CA (never told about any
// specific leaf) completes a real TLS handshake against the running server.
func TestEcsServerCmdRun_NativeMintsLeafFromCA(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	storeCaForTest(t, ctx)

	caCert, err := ctx.Store.GetEcsCaCert()
	require.NoError(t, err)

	cctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ctx.Ctx = cctx

	port := freeTestPort(t)
	ctx.Cli.Ecs.Server = EcsServerCmd{
		BindIP:      "127.0.0.1",
		Port:        port,
		DisableAuth: true,
	}
	cc := &ctx.Cli.Ecs.Server

	done := make(chan error, 1)
	go func() { done <- cc.Run(ctx) }()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	require.NoError(t, waitForEcsServerUp("https", addr, caCert, 5*time.Second),
		"native ecs server should mint a leaf from the stored CA and serve TLS")

	cancel()
	assert.NoError(t, <-done, "Run() should return nil on context cancellation")
}

// TestEcsServerCmdRun_NativeNoCA_SSLDisabled confirms that, with no CA
// configured, the native path leaves SSL disabled exactly as before this
// change (no persisted leaf to fall back to either).
func TestEcsServerCmdRun_NativeNoCA_SSLDisabled(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)

	caCert, err := ctx.Store.GetEcsCaCert()
	require.NoError(t, err)
	require.Empty(t, caCert, "sanity check: no CA should be configured")

	cctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ctx.Ctx = cctx

	port := freeTestPort(t)
	ctx.Cli.Ecs.Server = EcsServerCmd{
		BindIP:      "127.0.0.1",
		Port:        port,
		DisableAuth: true,
	}
	cc := &ctx.Cli.Ecs.Server

	done := make(chan error, 1)
	go func() { done <- cc.Run(ctx) }()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	require.NoError(t, waitForEcsServerUp("http", addr, "", 5*time.Second),
		"ecs server with no CA configured should serve plain HTTP")

	cancel()
	assert.NoError(t, <-done, "Run() should return nil on context cancellation")
}

// TestEcsServerCmdRun_NativeMalformedCA_ReturnsError confirms a malformed
// stored CA fails fast rather than silently falling back to no-TLS.
func TestEcsServerCmdRun_NativeMalformedCA_ReturnsError(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Store = &errStore{
		SecureStorage: ctx.Store,
		getEcsCaCert:  func() (string, error) { return "not a cert", nil },
		getEcsCaKey:   func() (string, error) { return "not a key", nil },
	}

	ctx.Cli.Ecs.Server = EcsServerCmd{
		BindIP:      "127.0.0.1",
		Port:        freeTestPort(t),
		DisableAuth: true,
	}
	cc := &ctx.Cli.Ecs.Server

	err := cc.Run(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to generate leaf certificate")
}

// genTestCertWithNotAfter builds a self-signed leaf good enough for
// warnIfCertExpiringSoon (it only needs a certutil.NotAfter-parseable PEM),
// with an arbitrary expiration so expiry-warning boundary cases are
// deterministic instead of depending on certutil.LeafValidity/CAValidity.
func genTestCertWithNotAfter(t *testing.T, notAfter time.Time) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    notAfter.Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestCertExpiryWarning(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		notAfter time.Time
		want     string
	}{
		{
			name:     "far from expiring",
			notAfter: now.Add(60 * 24 * time.Hour),
			want:     "",
		},
		{
			name:     "exactly at the warning window",
			notAfter: now.Add(ecsLeafCertExpiryWarningWindow),
			want:     "",
		},
		{
			name:     "just inside the warning window",
			notAfter: now.Add(ecsLeafCertExpiryWarningWindow - time.Second),
			want:     "SSL/TLS leaf certificate expires soon",
		},
		{
			name:     "expires right now",
			notAfter: now,
			want:     "SSL/TLS leaf certificate has expired",
		},
		{
			name:     "already expired",
			notAfter: now.Add(-24 * time.Hour),
			want:     "SSL/TLS leaf certificate has expired",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := certExpiryWarning("leaf certificate", tt.notAfter, now, ecsLeafCertExpiryWarningWindow)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWarnIfCertExpiringSoon_InvalidCert(t *testing.T) {
	tLogger := testlogger.NewTestLogger("DEBUG")
	defer tLogger.Close()

	oldLog := log
	log = tLogger
	defer func() { log = oldLog }()

	// Not a parseable certificate: NotAfter fails, so nothing should be logged.
	warnIfCertExpiringSoon("not a cert", "leaf certificate",
		"aws-sso setup ecs ssl --self-signed", ecsLeafCertExpiryWarningWindow)

	msg := testlogger.LogMessage{}
	assert.Error(t, tLogger.GetNext(&msg), "no warning should be logged when the certificate can't be parsed")
}

func TestWarnIfCertExpiringSoon_NotExpiring(t *testing.T) {
	tLogger := testlogger.NewTestLogger("DEBUG")
	defer tLogger.Close()

	oldLog := log
	log = tLogger
	defer func() { log = oldLog }()

	ca, err := certutil.GenerateCA()
	require.NoError(t, err)

	warnIfCertExpiringSoon(ca.CertPEM, "CA certificate",
		"aws-sso setup ecs ssl --rotate-ca", ecsCaCertExpiryWarningWindow)

	msg := testlogger.LogMessage{}
	assert.Error(t, tLogger.GetNext(&msg), "a CA valid for 10 years should not trigger a warning")
}

func TestWarnIfCertExpiringSoon_Expired(t *testing.T) {
	tLogger := testlogger.NewTestLogger("DEBUG")
	defer tLogger.Close()

	oldLog := log
	log = tLogger
	defer func() { log = oldLog }()

	certPEM := genTestCertWithNotAfter(t, time.Now().Add(-24*time.Hour))
	warnIfCertExpiringSoon(certPEM, "leaf certificate",
		"aws-sso setup ecs ssl --self-signed", ecsLeafCertExpiryWarningWindow)

	msg := testlogger.LogMessage{}
	require.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, "SSL/TLS leaf certificate has expired", msg.Message)
}

func TestEcsServerCmdAfterApply(t *testing.T) {
	tests := []struct {
		name     string
		cmd      EcsServerCmd
		wantAuth CommandAuth
	}{
		{
			name:     "docker mode ignores Default",
			cmd:      EcsServerCmd{Docker: true, Default: "any-profile"},
			wantAuth: AUTH_NO_CONFIG,
		},
		{
			name:     "Default set without docker requires auth",
			cmd:      EcsServerCmd{Default: "my-profile"},
			wantAuth: AUTH_REQUIRED,
		},
		{
			name:     "no Default and no docker skips auth",
			cmd:      EcsServerCmd{},
			wantAuth: AUTH_SKIP,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runCtx := &RunContext{}
			err := tt.cmd.AfterApply(runCtx)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAuth, runCtx.Auth)
		})
	}
}

func TestSetServerDefaultProfileNotFound(t *testing.T) {
	// Build a RunContext with an empty SSO cache so GetRoleByProfile returns "not found".
	c := &ssocache.Cache{SSO: map[string]*ssocache.SSOCache{}}
	ctx := &RunContext{
		Settings: newMinimalSettings(c),
		Cli:      &CLI{},
	}
	// s can be nil: the function returns before touching the server on error.
	err := setServerDefaultProfile(ctx, nil, "nonexistent-profile")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent-profile")
}

// TestEcsServerCmdRun_NativeStoreErrors: the native path reads three secrets out
// of the SecureStore before it can decide its security posture.  A failure on
// any of them has to abort the start rather than fall through to a server with
// auth or TLS silently switched off.
func TestEcsServerCmdRun_NativeStoreErrors(t *testing.T) {
	tests := []struct {
		name  string
		store func(inner storage.SecureStorage) *errStore
	}{
		{
			name: "bearer token unreadable",
			store: func(inner storage.SecureStorage) *errStore {
				return &errStore{
					SecureStorage:     inner,
					getEcsBearerToken: func() (string, error) { return "", errBoom },
				}
			},
		},
		{
			name: "CA certificate unreadable",
			store: func(inner storage.SecureStorage) *errStore {
				return &errStore{
					SecureStorage: inner,
					getEcsCaCert:  func() (string, error) { return "", errBoom },
				}
			},
		},
		{
			name: "CA key unreadable",
			store: func(inner storage.SecureStorage) *errStore {
				return &errStore{
					SecureStorage: inner,
					getEcsCaKey:   func() (string, error) { return "", errBoom },
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newSelfSignedTestCtx(t)
			ctx.Store = tt.store(ctx.Store)
			ctx.Cli.Ecs.Server = EcsServerCmd{BindIP: "127.0.0.1", Port: freeTestPort(t)}

			assert.ErrorIs(t, ctx.Cli.Ecs.Server.Run(ctx), errBoom)
		})
	}
}

// TestEcsServerCmdRun_NativeUnknownDefaultProfile: --default names a profile
// that isn't in the cache, so the server refuses to start rather than coming up
// without the credentials the user asked it to preload.
func TestEcsServerCmdRun_NativeUnknownDefaultProfile(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Settings = newMinimalSettings(&ssocache.Cache{SSO: map[string]*ssocache.SSOCache{}})
	ctx.Cli.Ecs.Server = EcsServerCmd{
		BindIP:      "127.0.0.1",
		Port:        freeTestPort(t),
		DisableAuth: true,
		Default:     "nonexistent-profile",
	}

	err := ctx.Cli.Ecs.Server.Run(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent-profile")
}

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/synfinatic/aws-sso-cli/internal/certutil"
	ssocache "github.com/synfinatic/aws-sso-cli/internal/sso/cache"
	testlogger "github.com/synfinatic/flexlog/test"
)

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
			notAfter: now.Add(ecsCertExpiryWarningWindow),
			want:     "",
		},
		{
			name:     "just inside the warning window",
			notAfter: now.Add(ecsCertExpiryWarningWindow - time.Second),
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
			got := certExpiryWarning("leaf certificate", tt.notAfter, now, ecsCertExpiryWarningWindow)
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
	warnIfCertExpiringSoon("not a cert", "leaf certificate", "aws-sso setup ecs ssl --self-signed")

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

	warnIfCertExpiringSoon(ca.CertPEM, "CA certificate", "aws-sso setup ecs ssl --rotate-ca")

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
	warnIfCertExpiringSoon(certPEM, "leaf certificate", "aws-sso setup ecs ssl --self-signed")

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

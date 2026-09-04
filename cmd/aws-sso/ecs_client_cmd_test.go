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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/synfinatic/aws-sso-cli/internal/certutil"
	testlogger "github.com/synfinatic/flexlog/test"
)

// selfSignedCertPEM generates a self-signed leaf cert PEM with the given
// NotAfter, for exercising warnIfCertExpiringSoon without waiting on
// certutil's fixed LeafValidity.
func selfSignedCertPEM(t *testing.T, notAfter time.Time) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
}

func withTestLogger(t *testing.T) *testlogger.TestLogger {
	t.Helper()

	tLogger := testlogger.NewTestLogger("DEBUG")
	oldLogger := log.Copy()
	log = tLogger
	t.Cleanup(func() {
		log = oldLogger
		tLogger.Close()
	})
	return tLogger
}

func TestWarnIfCertExpiringSoon_NoCert(t *testing.T) {
	tLogger := withTestLogger(t)

	warnIfCertExpiringSoon("")

	msg := testlogger.LogMessage{}
	assert.Error(t, tLogger.GetNext(&msg), "no log messages expected when no cert is configured")
}

func TestWarnIfCertExpiringSoon_FarFromExpiry(t *testing.T) {
	tLogger := withTestLogger(t)

	ca, err := certutil.GenerateCA()
	require.NoError(t, err)
	leaf, err := certutil.GenerateLeaf(ca)
	require.NoError(t, err)

	warnIfCertExpiringSoon(leaf.CertPEM)

	msg := testlogger.LogMessage{}
	assert.Error(t, tLogger.GetNext(&msg), "no log messages expected for a cert that isn't close to expiry")
}

func TestWarnIfCertExpiringSoon_NearExpiry(t *testing.T) {
	tLogger := withTestLogger(t)

	certPEM := selfSignedCertPEM(t, time.Now().Add(2*24*time.Hour))
	warnIfCertExpiringSoon(certPEM)

	msg := testlogger.LogMessage{}
	require.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, "WARN", strings.TrimSpace(msg.LevelStr))
	assert.Contains(t, msg.Message, "expiring soon")
}

func TestWarnIfCertExpiringSoon_InvalidCert(t *testing.T) {
	tLogger := withTestLogger(t)

	warnIfCertExpiringSoon("not a pem block")

	msg := testlogger.LogMessage{}
	require.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, "ERROR", strings.TrimSpace(msg.LevelStr))
}

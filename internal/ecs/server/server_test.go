package server

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
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/synfinatic/aws-sso-cli/internal/certutil"
	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	"github.com/synfinatic/aws-sso-cli/internal/ecs/client"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	testlogger "github.com/synfinatic/flexlog/test"
	"golang.org/x/net/nettest"
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

func newRequest(now time.Time) *ecs.ECSClientRequest {
	return &ecs.ECSClientRequest{
		ProfileName: "1234:FooBar",
		Creds: &storage.RoleCredentials{
			RoleName:        "FooBar",
			AccountId:       1234,
			AccessKeyId:     "AccessKeyId",
			SecretAccessKey: "SecretAccessKey",
			SessionToken:    "SessionToken",
			Expiration:      now.UnixMilli(),
		},
	}
}

func TestSlottedCreds(t *testing.T) {
	now := time.Now().Add(95 * time.Second)
	r := newRequest(now)
	es := &EcsServer{
		slottedCreds: map[string]*ecs.ECSClientRequest{},
	}

	// Add creds
	err := es.PutSlottedCreds(r)
	assert.NoError(t, err)

	// get those creds
	resp, err := es.GetSlottedCreds("1234:FooBar")
	assert.NoError(t, err)
	assert.Equal(t, r.ProfileName, resp.ProfileName)

	// can't find missing creds
	_, err = es.GetSlottedCreds("asdfsdf")
	assert.Error(t, err)

	// we can list our crds
	list := es.ListSlottedCreds()
	assert.Equal(t, 1, len(list))
	assert.Equal(t, r.ProfileName, list[0].ProfileName)

	// failure to add expired creds
	now = time.Now().Add(-5 * time.Second)
	err = es.PutSlottedCreds(newRequest(now))
	assert.Error(t, err)

	// didn't actually add the expired creds
	list = es.ListSlottedCreds()
	assert.Equal(t, 1, len(list))
	assert.Equal(t, r.ProfileName, list[0].ProfileName)

	// manually add expired creds which should not be listed
	es.slottedCreds["Expired"] = &ecs.ECSClientRequest{
		ProfileName: "expired",
		Creds: &storage.RoleCredentials{
			Expiration: now.UnixMilli(),
		},
	}
	list = es.ListSlottedCreds()
	assert.Equal(t, 1, len(list))

	// Success delete our creds
	err = es.DeleteSlottedCreds("1234:FooBar")
	assert.NoError(t, err)

	list = es.ListSlottedCreds()
	assert.Empty(t, list)

	// can't delete missing creds
	err = es.DeleteSlottedCreds("1234:FooBar")
	assert.Error(t, err)
}

func TestGetSlottedCreds_LogsAtInfo(t *testing.T) {
	tLogger := withTestLogger(t)

	es := &EcsServer{
		slottedCreds: map[string]*ecs.ECSClientRequest{
			"1234:FooBar": newRequest(time.Now().Add(95 * time.Second)),
		},
	}

	_, err := es.GetSlottedCreds("1234:FooBar")
	assert.NoError(t, err)

	msg := testlogger.LogMessage{}
	require.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, "INFO", strings.TrimSpace(msg.LevelStr))
	assert.Equal(t, "fetching creds", msg.Message)
}

func TestEcsServerErrorLog_LogsError(t *testing.T) {
	tLogger := withTestLogger(t)

	n, err := ecsServerErrorLog{}.Write([]byte("tls: bad record\n"))
	assert.NoError(t, err)
	assert.Equal(t, len("tls: bad record\n"), n)

	msg := testlogger.LogMessage{}
	require.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, "ERROR", strings.TrimSpace(msg.LevelStr))
	assert.Equal(t, "http server error", msg.Message)
	assert.Equal(t, "tls: bad record", msg.Error)
}

func TestNewEcsServer_SetsErrorLog(t *testing.T) {
	l, err := nettest.NewLocalListener("tcp")
	assert.NoError(t, err)

	s, err := NewEcsServer(context.TODO(), "", l, "", "")
	assert.NoError(t, err)
	defer s.Close()

	assert.NotNil(t, s.server.ErrorLog)
}

func TestBaseURL(t *testing.T) {
	l, err := nettest.NewLocalListener("tcp")
	assert.NoError(t, err)
	defer l.Close()

	es := &EcsServer{
		listener: l,
	}

	str := es.BaseURL()
	assert.Regexp(t, regexp.MustCompile(`^http://`), str)

	// check ssl
	es.privateKey = "test"
	es.certChain = "test"
	str = es.BaseURL()
	assert.Regexp(t, regexp.MustCompile(`^https://`), str)
}

func TestExpiredCredentials(t *testing.T) {
	e := ExpiredCredentials{}
	assert.Equal(t, "Expired Credentials", e.Error())
}

func TestServerWithAuth(t *testing.T) {
	tLogger := withTestLogger(t)

	l, err := nettest.NewLocalListener("tcp")
	assert.NoError(t, err)

	s, err := NewEcsServer(context.TODO(), "AuthToken", l, "", "")
	assert.NoError(t, err)
	defer s.Close()

	go func() {
		_ = s.Serve()
	}()

	res, err := http.Get(fmt.Sprintf("http://%s/", l.Addr()))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, res.StatusCode)

	msg := testlogger.LogMessage{}
	require.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, "WARN", strings.TrimSpace(msg.LevelStr))
	assert.Equal(t, "invalid authorization token", msg.Message)
}

func TestServerWithoutAuth(t *testing.T) {
	l, err := nettest.NewLocalListener("tcp")
	assert.NoError(t, err)

	s, err := NewEcsServer(context.TODO(), "", l, "", "")
	assert.NoError(t, err)
	defer s.Close()

	go func() {
		_ = s.Serve()
	}()

	res, err := http.Get(fmt.Sprintf("http://%s/", l.Addr()))
	assert.NoError(t, err)
	// nothing was loaded yet, so 404
	assert.Equal(t, http.StatusNotFound, res.StatusCode)
}

func TestServerWithSSL(t *testing.T) {
	l, err := nettest.NewLocalListener("tcp")
	assert.NoError(t, err)

	// replace loading from SecureStore
	privateKey, err := os.ReadFile("./testdata/localhost.key")
	assert.NoError(t, err)
	certChain, err := os.ReadFile("./testdata/localhost.crt")
	assert.NoError(t, err)

	s, err := NewEcsServer(context.TODO(), "", l, string(privateKey), string(certChain))
	assert.NoError(t, err)
	defer s.Close()

	go func() {
		_ = s.Serve()
	}()

	httpClient, err := client.NewHTTPClient(string(certChain))
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s/", l.Addr()), nil)
	assert.NoError(t, err)

	res, err := httpClient.Do(req) // nolint:gosec
	assert.NoError(t, err)
	// nothing was loaded yet, so 404
	assert.Equal(t, http.StatusNotFound, res.StatusCode)
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

	es := &EcsServer{}
	es.warnIfCertExpiringSoon()

	msg := testlogger.LogMessage{}
	assert.Error(t, tLogger.GetNext(&msg), "no log messages expected when no cert is configured")
}

func TestWarnIfCertExpiringSoon_FarFromExpiry(t *testing.T) {
	tLogger := withTestLogger(t)

	ca, err := certutil.GenerateCA()
	require.NoError(t, err)
	leaf, err := certutil.GenerateLeaf(ca)
	require.NoError(t, err)

	es := &EcsServer{certChain: leaf.CertPEM}
	es.warnIfCertExpiringSoon()

	msg := testlogger.LogMessage{}
	assert.Error(t, tLogger.GetNext(&msg), "no log messages expected for a cert that isn't close to expiry")
}

func TestWarnIfCertExpiringSoon_NearExpiry(t *testing.T) {
	tLogger := withTestLogger(t)

	certPEM := selfSignedCertPEM(t, time.Now().Add(2*24*time.Hour))
	es := &EcsServer{certChain: certPEM}
	es.warnIfCertExpiringSoon()

	msg := testlogger.LogMessage{}
	require.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, "WARN", strings.TrimSpace(msg.LevelStr))
	assert.Contains(t, msg.Message, "expiring soon")
}

func TestWarnIfCertExpiringSoon_InvalidCert(t *testing.T) {
	tLogger := withTestLogger(t)

	es := &EcsServer{certChain: "not a pem block"}
	es.warnIfCertExpiringSoon()

	msg := testlogger.LogMessage{}
	require.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, "ERROR", strings.TrimSpace(msg.LevelStr))
}

func TestDefaultHandlerPut_WarnsOnNearExpiryCert(t *testing.T) {
	tLogger := withTestLogger(t)

	certPEM := selfSignedCertPEM(t, time.Now().Add(2*24*time.Hour))
	dh := DefaultHandler{
		ecs: &EcsServer{
			certChain: certPEM,
			DefaultCreds: &ecs.ECSClientRequest{
				Creds: &storage.RoleCredentials{},
			},
		},
	}
	ts := httptest.NewServer(&dh)
	defer ts.Close()

	cr := ecs.ECSClientRequest{
		ProfileName: "TestProfileName",
		Creds: &storage.RoleCredentials{
			AccountId:       1111111,
			RoleName:        "myrole",
			AccessKeyId:     "AccessKeyId",
			SecretAccessKey: "SecretAccessKey",
			SessionToken:    "SessionToken",
			Expiration:      time.Now().Add(90 * time.Second).UnixMilli(),
		},
	}
	url := fmt.Sprintf("%s%s", ts.URL, ecs.DEFAULT_ROUTE)
	resp, err := submitRequest(t, url, cr)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	msg := testlogger.LogMessage{}
	require.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, "WARN", strings.TrimSpace(msg.LevelStr))
	assert.Contains(t, msg.Message, "expiring soon")
}

func TestPutSlottedCreds_WarnsOnNearExpiryCert(t *testing.T) {
	tLogger := withTestLogger(t)

	certPEM := selfSignedCertPEM(t, time.Now().Add(2*24*time.Hour))
	es := &EcsServer{
		certChain:    certPEM,
		slottedCreds: map[string]*ecs.ECSClientRequest{},
	}

	err := es.PutSlottedCreds(newRequest(time.Now().Add(90 * time.Second)))
	require.NoError(t, err)

	msg := testlogger.LogMessage{}
	require.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, "WARN", strings.TrimSpace(msg.LevelStr))
	assert.Contains(t, msg.Message, "expiring soon")
}

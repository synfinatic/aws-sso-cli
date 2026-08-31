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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/synfinatic/aws-sso-cli/internal/certutil"
	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	"golang.org/x/net/nettest"
)

func newHealthCheckServer() *EcsServer {
	return &EcsServer{
		DefaultCreds: &ecs.ECSClientRequest{
			Creds: &storage.RoleCredentials{},
		},
		slottedCreds: map[string]*ecs.ECSClientRequest{},
	}
}

func TestHealthCheckDefault(t *testing.T) {
	h := HealthCheckHandler{ecs: newHealthCheckServer()}
	ts := httptest.NewServer(&h)
	defer ts.Close()

	url := fmt.Sprintf("%s%s", ts.URL, ecs.HEALTHCHECK_ROUTE)

	// no credentials loaded
	res, err := http.Get(url) //nolint
	assert.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode)
	resp := healthCheckResponse{}
	assert.NoError(t, json.NewDecoder(res.Body).Decode(&resp))
	assert.Equal(t, "no credentials loaded", resp.Status)

	// valid credentials loaded
	soon := time.Now().Add(90 * time.Second)
	h.ecs.DefaultCreds = &ecs.ECSClientRequest{
		ProfileName: "123456789012:MyRole",
		Creds: &storage.RoleCredentials{
			RoleName:        "MyRole",
			AccountId:       123456789012,
			AccessKeyId:     "AKID",
			SecretAccessKey: "SAK",
			SessionToken:    "ST",
			Expiration:      soon.UnixMilli(),
		},
	}
	res, err = http.Get(url) //nolint
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	resp = healthCheckResponse{}
	assert.NoError(t, json.NewDecoder(res.Body).Decode(&resp))
	assert.Equal(t, "ok", resp.Status)
	assert.Equal(t, "123456789012:MyRole", resp.Profile)
	assert.NotEmpty(t, resp.Expires)

	// expired credentials
	h.ecs.DefaultCreds.Creds.Expiration = time.Now().Add(-5 * time.Second).UnixMilli()
	res, err = http.Get(url) //nolint
	assert.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode)
	resp = healthCheckResponse{}
	assert.NoError(t, json.NewDecoder(res.Body).Decode(&resp))
	assert.Equal(t, "credentials expired", resp.Status)

	// non-GET method
	res, err = http.Head(url) //nolint
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestHealthCheckSlot(t *testing.T) {
	h := HealthCheckHandler{ecs: newHealthCheckServer()}
	ts := httptest.NewServer(&h)
	defer ts.Close()

	profileName := "123456789012:SlottedRole"
	url := fmt.Sprintf("%s%s/slot/%s", ts.URL, ecs.HEALTHCHECK_ROUTE, profileName)

	// slot does not exist
	res, err := http.Get(url) //nolint
	assert.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode)
	resp := healthCheckResponse{}
	assert.NoError(t, json.NewDecoder(res.Body).Decode(&resp))
	assert.Equal(t, "slot not found", resp.Status)

	// load valid creds into the slot
	soon := time.Now().Add(90 * time.Second)
	assert.NoError(t, h.ecs.PutSlottedCreds(&ecs.ECSClientRequest{
		ProfileName: profileName,
		Creds: &storage.RoleCredentials{
			RoleName:        "SlottedRole",
			AccountId:       123456789012,
			AccessKeyId:     "AKID",
			SecretAccessKey: "SAK",
			SessionToken:    "ST",
			Expiration:      soon.UnixMilli(),
		},
	}))
	res, err = http.Get(url) //nolint
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	resp = healthCheckResponse{}
	assert.NoError(t, json.NewDecoder(res.Body).Decode(&resp))
	assert.Equal(t, "ok", resp.Status)
	assert.Equal(t, profileName, resp.Profile)
	assert.NotEmpty(t, resp.Expires)

	// expired creds in slot
	h.ecs.slottedCreds[profileName].Creds.Expiration = time.Now().Add(-5 * time.Second).UnixMilli()
	res, err = http.Get(url) //nolint
	assert.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode)
	resp = healthCheckResponse{}
	assert.NoError(t, json.NewDecoder(res.Body).Decode(&resp))
	assert.Equal(t, "credentials expired", resp.Status)
}

// TestHealthCheckBypassesAuth confirms the /healthcheck route responds even
// when the server is configured with a bearer token and no Authorization header is sent.
func TestHealthCheckBypassesAuth(t *testing.T) {
	l, err := nettest.NewLocalListener("tcp")
	assert.NoError(t, err)

	s, err := NewEcsServer(context.TODO(), "super-secret-token", l, "", "")
	assert.NoError(t, err)
	defer s.Close()

	go func() { _ = s.Serve() }()

	// /healthcheck should not require auth
	res, err := http.Get(fmt.Sprintf("http://%s%s", l.Addr(), ecs.HEALTHCHECK_ROUTE))
	if res != nil {
		defer res.Body.Close()
	}
	assert.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode) // no creds loaded, but not 403

	// / still requires auth
	res, err = http.Get(fmt.Sprintf("http://%s/", l.Addr()))
	if res != nil {
		defer res.Body.Close()
	}
	assert.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
}

// TestHealthCheckExpiredCert covers the case the container cannot fix itself: an
// expired serving certificate breaks every TLS client regardless of what
// credentials are loaded, so /healthcheck has to fail before the credential
// checks -- otherwise `docker compose` happily reports the server healthy and
// starts client containers that then fail with opaque TLS errors.
func TestHealthCheckExpiredCert(t *testing.T) {
	e := newHealthCheckServer()
	e.certNotAfter = time.Now().Add(-time.Hour)

	// loaded, unexpired credentials: the cert is the only thing wrong here
	soon := time.Now().Add(90 * time.Second)
	creds := &ecs.ECSClientRequest{
		ProfileName: "123456789012:MyRole",
		Creds: &storage.RoleCredentials{
			RoleName:        "MyRole",
			AccountId:       123456789012,
			AccessKeyId:     "AKID",
			SecretAccessKey: "SAK",
			SessionToken:    "ST",
			Expiration:      soon.UnixMilli(),
		},
	}
	e.DefaultCreds = creds
	e.slottedCreds["123456789012:MyRole"] = creds

	h := HealthCheckHandler{ecs: e}
	ts := httptest.NewServer(&h)
	defer ts.Close()

	for _, path := range []string{
		ecs.HEALTHCHECK_ROUTE,
		fmt.Sprintf("%s/slot/123456789012:MyRole", ecs.HEALTHCHECK_ROUTE),
	} {
		res, err := http.Get(ts.URL + path) //nolint
		assert.NoError(t, err)
		assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode, path)
		resp := healthCheckResponse{}
		assert.NoError(t, json.NewDecoder(res.Body).Decode(&resp))
		assert.Equal(t, certExpiredStatus, resp.Status, path)
		res.Body.Close()
	}
}

// TestCertExpired covers the plain-HTTP case: with TLS disabled there is no
// certificate to expire, so the healthcheck must not report one.
func TestCertExpired(t *testing.T) {
	e := newHealthCheckServer()
	assert.False(t, e.CertExpired(), "no certificate configured means nothing to expire")

	e.certNotAfter = time.Now().Add(time.Hour)
	assert.False(t, e.CertExpired())

	e.certNotAfter = time.Now().Add(-time.Second)
	assert.True(t, e.CertExpired())
}

// TestNewEcsServerParsesCertExpiry proves the expiry is read off the real
// certChain at construction, not left zero (which would make CertExpired always
// report false and silently defeat the check above).
func TestNewEcsServerParsesCertExpiry(t *testing.T) {
	ca, err := certutil.GenerateCA()
	assert.NoError(t, err)
	leaf, err := certutil.GenerateLeaf(certutil.KeyPair{CertPEM: ca.CertPEM, KeyPEM: ca.KeyPEM})
	assert.NoError(t, err)

	l, err := nettest.NewLocalListener("tcp")
	assert.NoError(t, err)
	defer l.Close()

	e, err := NewEcsServer(context.TODO(), "", l, leaf.KeyPEM, leaf.CertPEM)
	assert.NoError(t, err)
	assert.False(t, e.certNotAfter.IsZero(), "certNotAfter should be parsed from certChain")
	assert.False(t, e.CertExpired())

	// an unparseable chain is not fatal here -- Serve() rejects it properly via
	// tls.X509KeyPair -- but it must leave CertExpired reporting false rather
	// than failing every healthcheck.
	e, err = NewEcsServer(context.TODO(), "", l, leaf.KeyPEM, "not a cert")
	assert.NoError(t, err)
	assert.True(t, e.certNotAfter.IsZero())
	assert.False(t, e.CertExpired())
}

// TestHealthCheckMalformedPath: anything under /healthcheck that isn't the bare
// route or /slot/<profile> is a client error, not a health verdict -- reporting
// "ok" for a path we don't understand would make a typo look healthy.
func TestHealthCheckMalformedPath(t *testing.T) {
	h := HealthCheckHandler{ecs: newHealthCheckServer()}
	ts := httptest.NewServer(&h)
	defer ts.Close()

	for _, path := range []string{"/nonsense", "/slot", "/slot/", "/a/b/c"} {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(ts.URL + ecs.HEALTHCHECK_ROUTE + path) // nolint:gosec
			assert.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
}

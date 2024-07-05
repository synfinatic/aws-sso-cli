package client

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2024 Aaron Turner  <synfinatic at gmail dot com>
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
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

func TestCheckDoResponse(t *testing.T) {
	t.Parallel()

	resp := http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
	}
	assert.NoError(t, checkDoResponse(&resp))

	resp.StatusCode = http.StatusNotFound
	resp.Status = "404 Not Found"
	assert.Error(t, checkDoResponse(&resp))
}

func TestNewECSClient(t *testing.T) {
	t.Parallel()

	c := NewECSClient("localhost:4144", "token", "")
	assert.NotNil(t, c)
	assert.Equal(t, "localhost:4144", c.server)
	assert.Equal(t, "token", c.authToken)
	assert.NotEmpty(t, c.loadUrl)
	assert.NotEmpty(t, c.loadSlotUrl)
	assert.NotEmpty(t, c.profileUrl)
	assert.NotEmpty(t, c.listUrl)

	certChain, err := os.ReadFile("../server/testdata/localhost.crt")
	assert.NoError(t, err)
	c = NewECSClient("localhost:4144", "token", string(certChain))
	assert.NotNil(t, c)
}

func TestNewEcsClientFail(t *testing.T) {
	t.Parallel()
	assert.Panics(t, func() { NewECSClient("localhost:4144", "token", "foobar") })

	assert.Panics(t, func() { NewECSClient("localhost", "token", "") })

	assert.Panics(t, func() { NewECSClient("localhost:", "token", "") })

	assert.Panics(t, func() { NewECSClient(":4144", "token", "") })

	assert.Panics(t, func() { NewECSClient("localhost:foo", "token", "") })

	assert.Panics(t, func() { NewECSClient("localhost:0", "token", "") })

	assert.Panics(t, func() { NewECSClient("localhost:65536", "token", "") })
}

func TestECSClientLoadUrl(t *testing.T) {
	t.Parallel()

	c := NewECSClient("localhost:4144", "token", "")
	assert.NotNil(t, c)
	assert.Equal(t, "http://localhost:4144/", c.LoadUrl(""))

	url := c.LoadUrl("myprofile")
	assert.Equal(t, "http://localhost:4144/slot/myprofile", url)
}

func TestECSClientProfileUrl(t *testing.T) {
	t.Parallel()

	c := NewECSClient("localhost:4144", "token", "")
	assert.NotNil(t, c)
	assert.Equal(t, "http://localhost:4144/profile", c.ProfileUrl())
}

func TestECSClientListUrl(t *testing.T) {
	t.Parallel()

	c := NewECSClient("localhost:4144", "token", "")
	assert.NotNil(t, c)
	assert.Equal(t, "http://localhost:4144/slot", c.ListUrl())
}

func TestECSClientNewRequest(t *testing.T) {
	t.Parallel()

	c := NewECSClient("localhost:4144", "Bearer token", "")
	assert.NotNil(t, c)

	req, err := c.newRequest(http.MethodGet, "http://localhost:4144", nil)
	assert.NoError(t, err)
	assert.NotNil(t, req)
	assert.Equal(t, "http://localhost:4144", req.URL.String())
	assert.Equal(t, "Bearer token", req.Header.Get("Authorization"))
	assert.Equal(t, "application/json; charset=utf-8", req.Header.Get("Content-Type"))

	c = NewECSClient("localhost:4144", "", "")
	req, err = c.newRequest(http.MethodGet, "http://localhost:4144", nil)
	assert.NoError(t, err)
	assert.NotNil(t, req)
	assert.Equal(t, "http://localhost:4144", req.URL.String())
	assert.Equal(t, "", req.Header.Get("Authorization"))
	assert.Equal(t, "application/json; charset=utf-8", req.Header.Get("Content-Type"))

	_, err = c.newRequest("-55 foobar", "udp:adsf", nil)
	assert.Error(t, err)
}

func TestECSClientSubmitCredsPass(t *testing.T) {
	t.Parallel()

	// create mocked http server
	ts := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintln(w, "{\"code\": 200, \"message\": \"OK\"}")
			},
		),
	)
	defer ts.Close()

	c := NewECSClient("localhost:4144", "", "")
	c.loadUrl = ts.URL
	c.loadSlotUrl = ts.URL
	assert.NotNil(t, c)

	creds := storage.RoleCredentials{
		RoleName:        "role",
		AccountId:       123456,
		AccessKeyId:     "accesskey",
		SecretAccessKey: "secretkey",
		SessionToken:    "sessiontoken",
		Expiration:      1234567890,
	}

	err := c.SubmitCreds(&creds, "myprofile", false)
	assert.NoError(t, err)

	creds.RoleName = "role2"
	err = c.SubmitCreds(&creds, "myotherprofile", true)
	assert.NoError(t, err)

	c.loadUrl = "http://localhost:4144"
	err = c.SubmitCreds(&creds, "myprofile", false)
	assert.Error(t, err)

	c.loadSlotUrl = "http://localhost:4144"
	err = c.SubmitCreds(&creds, "myprofile", true)
	assert.Error(t, err)
}

func TestECSClientSubmitCredsFail(t *testing.T) {
	t.Parallel()

	// create mocked http server
	ts := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprintln(w, "{\"code\": 404, \"message\": \"404 Error\"}")
			},
		),
	)
	defer ts.Close()

	c := NewECSClient("localhost:4144", "token", "")
	c.loadUrl = ts.URL
	assert.NotNil(t, c)

	creds := &storage.RoleCredentials{
		RoleName:        "role",
		AccountId:       123456,
		AccessKeyId:     "accesskey",
		SecretAccessKey: "secretkey",
		SessionToken:    "sessiontoken",
		Expiration:      1234567890,
	}

	err := c.SubmitCreds(creds, "myprofile", false)
	assert.Error(t, err)
}

func TestECSGetProfile(t *testing.T) {
	t.Parallel()

	lpr := ecs.ListProfilesResponse{
		ProfileName:  "myprofile",
		AccountIdPad: "123456",
		RoleName:     "role",
		Expiration:   1234567890,
		Expires:      "1h 23m 45s",
	}

	// create mocked http server
	ts := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				ecs.WriteListProfileResponse(w, lpr)
			},
		),
	)
	defer ts.Close()

	c := NewECSClient("localhost:4144", "token", "")
	assert.NotNil(t, c)
	c.profileUrl = ts.URL

	lprResp, err := c.GetProfile()
	assert.NoError(t, err)
	assert.Equal(t, lpr, lprResp)

	c.profileUrl = "http//localhost:4144"
	_, err = c.GetProfile()
	assert.Error(t, err)

	ts2 := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintln(w, "bad json")
			},
		),
	)
	defer ts2.Close()

	c.profileUrl = ts2.URL
	_, err = c.GetProfile()
	assert.Error(t, err)
}

func TestECSAuthFailures(t *testing.T) {
	t.Parallel()

	// create mocked http server
	ts := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				ecs.WriteMessage(w, "Invalid authorization token", http.StatusForbidden)
			},
		),
	)
	defer ts.Close()

	c := NewECSClient("localhost:4144", "token", "")
	assert.NotNil(t, c)
	c.profileUrl = ts.URL

	_, err := c.GetProfile()
	assert.Error(t, err)

	_, err = c.ListProfiles()
	assert.Error(t, err)
}

func TestECSListProfiles(t *testing.T) {
	t.Parallel()

	lpr := []ecs.ListProfilesResponse{
		{
			ProfileName:  "myprofile",
			AccountIdPad: "000001234567",
			RoleName:     "role",
			Expiration:   1234567890,
			Expires:      "1h 23m 45s",
		},
		{
			ProfileName:  "myotherprofile",
			AccountIdPad: "000001234567",
			RoleName:     "role2",
			Expiration:   1234567890,
			Expires:      "1h 23m 45s",
		},
	}

	// create mocked http server
	ts := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				ecs.WriteListProfilesResponse(w, lpr)
			},
		),
	)
	defer ts.Close()

	c := NewECSClient("localhost:4144", "token", "")
	c.listUrl = ts.URL
	assert.NotNil(t, c)

	lprResp, err := c.ListProfiles()
	assert.NoError(t, err)
	assert.Equal(t, lpr, lprResp)

	c.listUrl = "http://localhost:4144"
	_, err = c.ListProfiles()
	assert.Error(t, err)

	// auth error
	ts2 := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				ecs.WriteMessage(w, "Invalid authorization token", http.StatusForbidden)
			},
		),
	)
	defer ts2.Close()
	c.listUrl = ts2.URL
	_, err = c.ListProfiles()
	assert.Error(t, err)
}

func TestECSDelete(t *testing.T) {
	t.Parallel()

	// create mocked http server
	ts := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				ecs.OK(w)
			},
		),
	)
	defer ts.Close()

	c := NewECSClient("localhost:4144", "token", "")
	c.loadUrl = ts.URL
	c.loadSlotUrl = ts.URL
	assert.NotNil(t, c)

	err := c.Delete("myprofile")
	assert.NoError(t, err)

	c.loadUrl = "http://localhost:4144"
	c.loadSlotUrl = "http://localhost:4144"
	err = c.Delete("foo")
	assert.Error(t, err)
}

func TestNewHTTPClient(t *testing.T) {
	t.Parallel()

	cert, err := os.ReadFile("../server/testdata/localhost.crt")
	assert.NoError(t, err)

	c, err := NewHTTPClient(string(cert))
	assert.NoError(t, err)
	assert.NotNil(t, c)

	_, err = NewHTTPClient("foobar")
	assert.Error(t, err)
}

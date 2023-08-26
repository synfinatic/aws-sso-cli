package server

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2023 Aaron Turner  <synfinatic at gmail dot com>
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
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

func TestDefaultGet(t *testing.T) {
	dh := DefaultHandler{
		ecs: &EcsServer{
			DefaultCreds: &ecs.ECSClientRequest{
				ProfileName: "",
				Creds:       &storage.RoleCredentials{},
			},
		},
	}
	ts := httptest.NewServer(&dh)
	defer ts.Close()

	url := fmt.Sprintf("%s%s", ts.URL, ecs.DEFAULT_ROUTE)
	res, err := http.Get(url) //nolint
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, res.StatusCode)

	soon := time.Now().Add(90 * time.Second)
	dh.ecs.DefaultCreds.ProfileName = "MyProfile"
	dh.ecs.DefaultCreds.Creds = &storage.RoleCredentials{
		RoleName:        "ProfileName",
		AccountId:       1111111,
		AccessKeyId:     "AccessKeyId",
		SecretAccessKey: "SecretAccessKey",
		SessionToken:    "SessionToken",
		Expiration:      soon.UnixMilli(),
	}

	res, err = http.Get(url) //nolint
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	creds := map[string]string{}
	err = json.NewDecoder(res.Body).Decode(&creds)
	assert.NoError(t, err)
	assert.Equal(t, "SessionToken", creds["Token"])
	assert.Equal(t, "AccessKeyId", creds["AccessKeyId"])

	// check expired
	dh.ecs.DefaultCreds.Creds.Expiration = time.Now().UnixMilli()
	res, err = http.Get(url) //nolint
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, res.StatusCode)
}

func submitRequest(t *testing.T, url string, cr ecs.ECSClientRequest) (*http.Response, error) {
	j, err := json.Marshal(cr)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(j))
	assert.NoError(t, err)

	req.Header.Set("Content-Type", ecs.CHARSET_JSON)
	client := &http.Client{}
	return client.Do(req)
}

func TestDefaultPut(t *testing.T) {
	dh := DefaultHandler{
		ecs: &EcsServer{
			DefaultCreds: &ecs.ECSClientRequest{
				ProfileName: "",
				Creds:       &storage.RoleCredentials{},
			},
		},
	}
	ts := httptest.NewServer(&dh)
	defer ts.Close()

	// empty
	cr := ecs.ECSClientRequest{}
	url := fmt.Sprintf("%s%s", ts.URL, ecs.DEFAULT_ROUTE)

	resp, err := submitRequest(t, url, cr)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	// Incomplete
	cr.ProfileName = "TestProfileName"
	resp, err = submitRequest(t, url, cr)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	// Complete
	cr.Creds = &storage.RoleCredentials{
		AccountId:       1111111,
		RoleName:        "myrole",
		AccessKeyId:     "AccessKeyId",
		SecretAccessKey: "SecretAccessKey",
		SessionToken:    "SessionToken",
		Expiration:      time.Now().Add(90 * time.Second).UnixMilli(),
	}
	resp, err = submitRequest(t, url, cr)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Expired
	cr.Creds.Expiration = time.Now().UnixMilli()
	resp, err = submitRequest(t, url, cr)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestDefaultDelete(t *testing.T) {
	dh := DefaultHandler{
		ecs: &EcsServer{
			DefaultCreds: &ecs.ECSClientRequest{
				ProfileName: "Foo",
				Creds:       &storage.RoleCredentials{},
			},
		},
	}
	ts := httptest.NewServer(&dh)
	defer ts.Close()

	url := fmt.Sprintf("%s%s", ts.URL, ecs.DEFAULT_ROUTE)

	req, err := http.NewRequest(http.MethodDelete, url, bytes.NewBuffer([]byte{}))
	assert.NoError(t, err)

	req.Header.Set("Content-Type", ecs.CHARSET_JSON)
	client := &http.Client{}
	resp, err := client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "", dh.ecs.DefaultCreds.ProfileName)

	// can't delete again
	resp, err = client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestDefaultDefault(t *testing.T) {
	dh := DefaultHandler{
		ecs: &EcsServer{},
	}
	ts := httptest.NewServer(&dh)
	defer ts.Close()

	url := fmt.Sprintf("%s%s", ts.URL, ecs.DEFAULT_ROUTE)
	res, err := http.Head(url) //nolint
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

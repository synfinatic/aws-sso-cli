package server

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
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

func TestSlottedGet(t *testing.T) {
	soon := time.Now().Add(90 * time.Second)
	sh := SlottedHandler{
		ecs: &EcsServer{
			slottedCreds: map[string]*ecs.ECSClientRequest{
				"Example": {
					ProfileName: "Example",
					Creds: &storage.RoleCredentials{
						RoleName:        "ProfileName",
						AccountId:       1111111,
						AccessKeyId:     "AccessKeyId",
						SecretAccessKey: "SecretAccessKey",
						SessionToken:    "SessionToken",
						Expiration:      soon.UnixMilli(),
					},
				},
			},
		},
	}
	ts := httptest.NewServer(&sh)
	defer ts.Close()

	// does not exist
	url := fmt.Sprintf("%s%s/%s", ts.URL, ecs.SLOT_ROUTE, "MissingExample")
	res, err := http.Get(url) //nolint
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, res.StatusCode)

	// exists
	url = fmt.Sprintf("%s%s/%s", ts.URL, ecs.SLOT_ROUTE, "Example")
	res, err = http.Get(url) //nolint
	assert.Equal(t, http.StatusOK, res.StatusCode)
	creds := map[string]string{}
	err = json.NewDecoder(res.Body).Decode(&creds)
	assert.NoError(t, err)
	assert.Equal(t, "SessionToken", creds["Token"])
	assert.Equal(t, "AccessKeyId", creds["AccessKeyId"])

	// list of profiles
	url = fmt.Sprintf("%s%s/", ts.URL, ecs.SLOT_ROUTE)
	res, err = http.Get(url) //nolint
	assert.Equal(t, http.StatusOK, res.StatusCode)
	lpr := []ecs.ListProfilesResponse{}
	err = json.NewDecoder(res.Body).Decode(&lpr)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(lpr))
	assert.Equal(t, "Example", lpr[0].ProfileName)
	assert.Equal(t, "ProfileName", lpr[0].RoleName)
}

func submitSlotRequest(t *testing.T, url string, cr ecs.ECSClientRequest) (*http.Response, error) {
	j, err := json.Marshal(cr)
	assert.NoError(t, err)

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(j))
	assert.NoError(t, err)

	req.Header.Set("Content-Type", ecs.CHARSET_JSON)
	client := &http.Client{}
	return client.Do(req)
}

func TestSlottedPut(t *testing.T) {
	sh := SlottedHandler{
		ecs: &EcsServer{
			slottedCreds: map[string]*ecs.ECSClientRequest{},
		},
	}
	ts := httptest.NewServer(&sh)
	defer ts.Close()

	// empty
	cr := ecs.ECSClientRequest{}
	url := fmt.Sprintf("%s%s/Example", ts.URL, ecs.SLOT_ROUTE)
	resp, err := submitSlotRequest(t, url, cr)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	// not empty
	cr.ProfileName = "TestProfileName"
	resp, err = submitSlotRequest(t, url, cr)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	cr.Creds = &storage.RoleCredentials{
		AccountId:       1111111,
		RoleName:        "myrole",
		AccessKeyId:     "AccessKeyId",
		SecretAccessKey: "SecretAccessKey",
		SessionToken:    "SessionToken",
		Expiration:      time.Now().Add(90 * time.Second).UnixMilli(),
	}
	resp, err = submitSlotRequest(t, url, cr)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// expired
	cr.Creds.Expiration = time.Now().UnixMilli()
	resp, err = submitSlotRequest(t, url, cr)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestSlottedDelete(t *testing.T) {
	sh := SlottedHandler{
		ecs: &EcsServer{
			slottedCreds: map[string]*ecs.ECSClientRequest{
				"Foo": {
					ProfileName: "Foo",
					Creds:       &storage.RoleCredentials{},
				},
			},
		},
	}
	ts := httptest.NewServer(&sh)
	defer ts.Close()

	url := fmt.Sprintf("%s%s/Foo", ts.URL, ecs.SLOT_ROUTE)

	req, err := http.NewRequest(http.MethodDelete, url, bytes.NewBuffer([]byte{}))
	assert.NoError(t, err)

	req.Header.Set("Content-Type", ecs.CHARSET_JSON)
	client := &http.Client{}
	resp, err := client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_, ok := sh.ecs.slottedCreds["Foo"]
	assert.False(t, ok)

	// can't delete again
	resp, err = client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestSlottedDefault(t *testing.T) {
	sh := SlottedHandler{
		ecs: &EcsServer{},
	}
	ts := httptest.NewServer(&sh)
	defer ts.Close()

	url := fmt.Sprintf("%s%s/Foo", ts.URL, ecs.SLOT_ROUTE)
	res, err := http.Head(url) //nolint
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestGetProfileName(t *testing.T) {
	u, _ := url.Parse("http://localhost:4144/slot/Foo")
	profile := GetProfileName(u)
	assert.Equal(t, "Foo", profile)

	u, _ = url.Parse("http://localhost:4144/slot")
	profile = GetProfileName(u)
	assert.Equal(t, "", profile)

	u, _ = url.Parse("http://localhost:4144/foo/Foo")
	profile = GetProfileName(u)
	assert.Equal(t, "", profile)

	u, _ = url.Parse("http://localhost:4144/sot/Foo/Bar")
	profile = GetProfileName(u)
	assert.Equal(t, "", profile)
}

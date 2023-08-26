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

func TestProfileGet(t *testing.T) {
	ph := ProfileHandler{
		ecs: &EcsServer{
			DefaultCreds: &ecs.ECSClientRequest{
				ProfileName: "",
				Creds:       &storage.RoleCredentials{},
			},
		},
	}
	ts := httptest.NewServer(&ph)
	defer ts.Close()

	url := fmt.Sprintf("%s%s", ts.URL, ecs.PROFILE_ROUTE)
	res, err := http.Get(url) //nolint
	assert.NoError(t, err)

	msg := ecs.Message{}
	err = json.NewDecoder(res.Body).Decode(&msg)
	assert.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("%d", http.StatusNotFound), msg.Code)

	soon := time.Now().Add(90 * time.Second)
	ph.ecs.DefaultCreds.ProfileName = "000001111111:ProfileName"
	ph.ecs.DefaultCreds.Creds = &storage.RoleCredentials{
		RoleName:        "ProfileName",
		AccountId:       1111111,
		AccessKeyId:     "AccessKeyId",
		SecretAccessKey: "SecretAccessKey",
		SessionToken:    "SessionToken",
		Expiration:      soon.UnixMilli(),
	}

	res, err = http.Get(url) //nolint
	assert.NoError(t, err)
	lpr := ecs.ListProfilesResponse{}
	err = json.NewDecoder(res.Body).Decode(&lpr)
	assert.NoError(t, err)
	assert.Equal(t, "000001111111:ProfileName", lpr.ProfileName)
	assert.Equal(t, "ProfileName", lpr.RoleName)

	ph.ecs.DefaultCreds.Creds.Expiration = time.Now().UnixMilli()
	res, err = http.Get(url) //nolint
	assert.NoError(t, err)
	err = json.NewDecoder(res.Body).Decode(&msg)
	assert.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("%d", http.StatusNotFound), msg.Code)

	res, err = http.Head(url) //nolint
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

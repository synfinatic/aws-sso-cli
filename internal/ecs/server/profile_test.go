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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	testlogger "github.com/synfinatic/flexlog/test"
)

func TestProfileGet(t *testing.T) {
	tLogger := withTestLogger(t)

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

	logMsg := testlogger.LogMessage{}
	require.NoError(t, tLogger.GetNext(&logMsg))
	assert.Equal(t, "INFO", strings.TrimSpace(logMsg.LevelStr))
	assert.Equal(t, "fetching default profile", logMsg.Message)

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

	logMsg = testlogger.LogMessage{}
	require.NoError(t, tLogger.GetNext(&logMsg))
	assert.Equal(t, "INFO", strings.TrimSpace(logMsg.LevelStr))
	assert.Equal(t, "fetching default profile", logMsg.Message)

	ph.ecs.DefaultCreds.Creds.Expiration = time.Now().UnixMilli()
	res, err = http.Get(url) //nolint
	assert.NoError(t, err)
	err = json.NewDecoder(res.Body).Decode(&msg)
	assert.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("%d", http.StatusNotFound), msg.Code)

	logMsg = testlogger.LogMessage{}
	require.NoError(t, tLogger.GetNext(&logMsg))
	assert.Equal(t, "INFO", strings.TrimSpace(logMsg.LevelStr))
	assert.Equal(t, "fetching default profile", logMsg.Message)

	res, err = http.Head(url) //nolint
	assert.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)

	logMsg = testlogger.LogMessage{}
	require.NoError(t, tLogger.GetNext(&logMsg))
	assert.Equal(t, "ERROR", strings.TrimSpace(logMsg.LevelStr))
	assert.Equal(t, "Invalid request", logMsg.Message)
}

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

func TestWriteCreds(t *testing.T) {
	w := httptest.NewRecorder()
	soon := time.Now().Add(90 * time.Second)
	creds := &storage.RoleCredentials{
		AccessKeyId:     "AccessKeyId",
		SecretAccessKey: "SecretAccessKey",
		SessionToken:    "Token",
		Expiration:      soon.UnixMilli(),
	}
	WriteCreds(w, creds)

	r := w.Result()
	outCreds := map[string]string{}
	err := json.NewDecoder(r.Body).Decode(&outCreds)
	assert.NoError(t, err)
	assert.Equal(t, "Token", outCreds["Token"])

	w = httptest.NewRecorder()

	creds.Expiration = time.Now().UnixMilli()
	WriteCreds(w, creds)
	r = w.Result()
	msg := Message{}
	err = json.NewDecoder(r.Body).Decode(&msg)
	assert.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("%d", http.StatusNotFound), msg.Code)
}

func TestWriteListProfilesResponse(t *testing.T) {
	w := httptest.NewRecorder()

	lpr := []ecs.ListProfilesResponse{
		{
			ProfileName:  "000001234567:TestingRole",
			RoleName:     "TestingRole",
			AccountIdPad: "000001234567",
			Expiration:   23455457475,
			Expires:      "some string",
		},
		{
			ProfileName:  "000001234567:AnotherRole",
			RoleName:     "AnotherRole",
			AccountIdPad: "000001234567",
			Expiration:   23455457475,
			Expires:      "another string",
		},
	}
	WriteListProfilesResponse(w, lpr)

	r := w.Result()
	resp := []ecs.ListProfilesResponse{}
	err := json.NewDecoder(r.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(resp))
	assert.Equal(t, "TestingRole", resp[0].RoleName)
	assert.Equal(t, "AnotherRole", resp[1].RoleName)
}

func TestOK(t *testing.T) {
	w := httptest.NewRecorder()
	OK(w)
	r := w.Result()
	assert.Equal(t, http.StatusOK, r.StatusCode)
	msg := Message{}
	err := json.NewDecoder(r.Body).Decode(&msg)
	assert.NoError(t, err)
	assert.Equal(t, "OK", msg.Message)
	assert.Equal(t, fmt.Sprintf("%d", http.StatusOK), msg.Code)
}

func TestExpired(t *testing.T) {
	w := httptest.NewRecorder()
	Expired(w)
	r := w.Result()
	assert.Equal(t, http.StatusNotFound, r.StatusCode)
	msg := Message{}
	err := json.NewDecoder(r.Body).Decode(&msg)
	assert.NoError(t, err)
	assert.Equal(t, "Credentials expired", msg.Message)
	assert.Equal(t, fmt.Sprintf("%d", http.StatusNotFound), msg.Code)
}

func TestUnavailable(t *testing.T) {
	w := httptest.NewRecorder()
	Unavailable(w)
	r := w.Result()
	assert.Equal(t, http.StatusNotFound, r.StatusCode)
	msg := Message{}
	err := json.NewDecoder(r.Body).Decode(&msg)
	assert.NoError(t, err)
	assert.Equal(t, "Credentials unavailable", msg.Message)
	assert.Equal(t, fmt.Sprintf("%d", http.StatusNotFound), msg.Code)
}

func TestInvalid(t *testing.T) {
	w := httptest.NewRecorder()
	Invalid(w)
	r := w.Result()
	assert.Equal(t, http.StatusBadRequest, r.StatusCode)
	msg := Message{}
	err := json.NewDecoder(r.Body).Decode(&msg)
	assert.NoError(t, err)
	assert.Equal(t, "Bad request", msg.Message)
	assert.Equal(t, fmt.Sprintf("%d", http.StatusBadRequest), msg.Code)
}

func TestInternalServerError(t *testing.T) {
	w := httptest.NewRecorder()
	InternalServerErrror(w, fmt.Errorf("Example error"))
	r := w.Result()
	assert.Equal(t, http.StatusInternalServerError, r.StatusCode)
	msg := Message{}
	err := json.NewDecoder(r.Body).Decode(&msg)
	assert.NoError(t, err)
	assert.Equal(t, "Example error", msg.Message)
	assert.Equal(t, fmt.Sprintf("%d", http.StatusInternalServerError), msg.Code)
}

func TestJSONResponse(t *testing.T) {
	w := httptest.NewRecorder()
	JSONResponse(w, make(chan int))
	r := w.Result()
	assert.Equal(t, http.StatusInternalServerError, r.StatusCode)
}

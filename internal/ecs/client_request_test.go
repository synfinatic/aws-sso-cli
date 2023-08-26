package ecs

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2022 Aaron Turner  <synfinatic at gmail dot com>
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
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

func TestReadClientRequest(t *testing.T) {
	soon := time.Now().Add(90 * time.Second)
	cr := ECSClientRequest{
		ProfileName: "000001111111:TestProfile",
		Creds: &storage.RoleCredentials{
			RoleName:        "TestProfile",
			AccountId:       1111111,
			AccessKeyId:     "AccessKeyId",
			SecretAccessKey: "SecretAccessKey",
			SessionToken:    "SessionToken",
			Expiration:      soon.UnixMilli(),
		},
	}
	w := httptest.NewRecorder()
	WriteCreds(w, cr.Creds)

	r := w.Result()
	outCreds := map[string]string{}
	err := json.NewDecoder(r.Body).Decode(&outCreds)
	assert.NoError(t, err)
	assert.Equal(t, "SessionToken", outCreds["Token"])

	w2 := httptest.NewRecorder()

	cr.Creds.Expiration = time.Now().UnixMilli()
	WriteCreds(w2, cr.Creds)
	r = w2.Result()
	msg := Message{}
	err = json.NewDecoder(r.Body).Decode(&msg)
	assert.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("%d", http.StatusNotFound), msg.Code)
}

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

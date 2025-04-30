package ecs

/*
 * AWS SSO CLI
 * Copyright (c) 2021-202 Aaron Turner  <synfinatic at gmail dot com>
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
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

func TestValidate(t *testing.T) {
	soon := time.Now().Add(90 * time.Second)
	cr := &ECSClientRequest{
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

	err := cr.Validate()
	assert.NoError(t, err)

	cr.Creds = nil
	err = cr.Validate()
	assert.ErrorContains(t, err, "Creds")

	cr.ProfileName = ""
	err = cr.Validate()
	assert.ErrorContains(t, err, "ProfileName")
}

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

	body, _ := json.Marshal(cr)
	r := httptest.NewRequest(http.MethodPut, fmt.Sprintf("%s/Foobar", DEFAULT_ROUTE), bytes.NewReader(body))
	ecr, err := ReadClientRequest(r)
	assert.NoError(t, err)
	assert.Equal(t, "000001111111:TestProfile", ecr.ProfileName)
	assert.Equal(t, int64(1111111), ecr.Creds.AccountId)

	msg := Message{
		Code:    "2344",
		Message: "a message",
	}
	body, _ = json.Marshal(msg)
	r = httptest.NewRequest(http.MethodPut, fmt.Sprintf("%s/Foobar", DEFAULT_ROUTE), bytes.NewReader(body))
	_, err = ReadClientRequest(r)
	assert.ErrorContains(t, err, "missing")

	body = []byte{'{', '[', ','}
	r = httptest.NewRequest(http.MethodPut, fmt.Sprintf("%s/Foobar", DEFAULT_ROUTE), bytes.NewReader(body))
	_, err = ReadClientRequest(r)
	assert.ErrorContains(t, err, "parsing json")
}

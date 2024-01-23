package ecs

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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

func TestNewListProfileResponse(t *testing.T) {
	now := time.Now().Add(5 * time.Second)

	cr := ECSClientRequest{
		ProfileName: "testing",
		Creds: &storage.RoleCredentials{
			RoleName:        "TestingRole",
			AccountId:       1234567,
			AccessKeyId:     "AccessKeyId",
			SecretAccessKey: "SecretAccessKey",
			SessionToken:    "SessionToken",
			Expiration:      now.UnixMilli(),
		},
	}

	lpr := NewListProfileRepsonse(&cr)
	assert.Equal(t, "testing", lpr.ProfileName)
	assert.Equal(t, "000001234567", lpr.AccountIdPad)
	assert.Equal(t, "TestingRole", lpr.RoleName)
	assert.Equal(t, now.Unix(), lpr.Expiration)
	remain, _ := utils.TimeRemain(now.Unix(), true)
	assert.Equal(t, remain, lpr.Expires)
}

func TestGetHeader(t *testing.T) {
	lpr := &ListProfilesResponse{
		ProfileName:  "000001234567:TestingRole",
		RoleName:     "TestingRole",
		AccountIdPad: "000001234567",
		Expiration:   23455457475,
		Expires:      "some string",
	}

	s, err := lpr.GetHeader("Expires")
	assert.NoError(t, err)
	assert.Equal(t, "Expires", s)
	_, err = lpr.GetHeader("ExpiresToMuch")
	assert.Error(t, err)
}

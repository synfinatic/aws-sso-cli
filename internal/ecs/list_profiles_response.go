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
	"reflect"

	"github.com/synfinatic/aws-sso-cli/internal/utils"
	"github.com/synfinatic/gotable"
)

type ListProfilesResponse struct {
	ProfileName  string `json:"ProfileName" header:"ProfileName"`
	AccountIdPad string `json:"AccountId" header:"AccountIdPad"`
	RoleName     string `json:"RoleName" header:"RoleName"`
	Expiration   int64  `json:"Expiration" header:"Expiration"`
	Expires      string `json:"Expires" header:"Expires"`
}

func NewListProfileRepsonse(cr *ECSClientRequest) ListProfilesResponse {
	exp, _ := utils.TimeRemain(cr.Creds.Expiration/1000, true)
	return ListProfilesResponse{
		ProfileName:  cr.ProfileName,
		AccountIdPad: cr.Creds.AccountIdStr(),
		RoleName:     cr.Creds.RoleName,
		Expiration:   cr.Creds.Expiration / 1000,
		Expires:      exp,
	}
}

// GetHeader is required for GenerateTable()
func (lpr ListProfilesResponse) GetHeader(fieldName string) (string, error) {
	v := reflect.ValueOf(lpr)
	return gotable.GetHeaderTag(v, fieldName)
}

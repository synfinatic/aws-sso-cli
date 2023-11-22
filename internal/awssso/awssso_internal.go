package awssso

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
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/sso/types"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

// makeRoleInfo takes the sso.types.RoleInfo and adds it onto our as.Roles[accountId] list
func (as *AWSSSO) makeRoleInfo(account AccountInfo, i int, r ssotypes.RoleInfo) {
	var via string

	aId, _ := strconv.ParseInt(account.AccountId, 10, 64)
	ssoRole, err := as.SSOConfig.GetRole(aId, aws.ToString(r.RoleName))
	if err != nil && len(ssoRole.Via) > 0 {
		via = ssoRole.Via
	}

	as.rolesLock.Lock()
	defer as.rolesLock.Unlock()
	as.Roles[account.AccountId] = append(as.Roles[account.AccountId], RoleInfo{
		Id:           i,
		AccountId:    aws.ToString(r.AccountId),
		Arn:          utils.MakeRoleARN(aId, aws.ToString(r.RoleName)),
		RoleName:     aws.ToString(r.RoleName),
		AccountName:  account.AccountName,
		EmailAddress: account.EmailAddress,
		SSORegion:    as.SsoRegion,
		StartUrl:     as.StartUrl,
		Via:          via,
	})
}

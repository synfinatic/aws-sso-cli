package main

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
	"fmt"

	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

type SelectCliArgs struct {
	Arn       string
	AccountId int64
	RoleName  string
	Profile   string
}

func NewSelectCliArgs(arn string, accountId int64, role, profile string) *SelectCliArgs {
	return &SelectCliArgs{
		Arn:       arn,
		AccountId: accountId,
		RoleName:  role,
		Profile:   profile,
	}
}

func (a *SelectCliArgs) Update(ctx *RunContext) error {
	if a.AccountId != 0 && a.RoleName != "" {
		return nil
	} else if a.Profile != "" {
		cache := ctx.Settings.Cache.GetSSO()
		rFlat, err := cache.Roles.GetRoleByProfile(a.Profile, ctx.Settings)
		if err != nil {
			return err
		}

		a.AccountId = rFlat.AccountId
		a.RoleName = rFlat.RoleName

		return nil
	} else if a.Arn != "" {
		accountId, role, err := utils.ParseRoleARN(a.Arn)
		if err != nil {
			return err
		}
		a.AccountId = accountId
		a.RoleName = role

		return nil
	}
	return fmt.Errorf("Please specify both --account and --role")
}

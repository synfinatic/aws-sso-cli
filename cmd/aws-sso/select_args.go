package main

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
	"fmt"

	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

type SelectCliArgs struct {
	Arn       string
	AccountId int64
	RoleName  string
	Profile   string
}

type InvalidArgsError struct {
	msg string
	arg string
}

func (e *InvalidArgsError) Error() string {
	if e.arg != "" {
		return fmt.Sprintf(e.msg, e.arg)
	}
	return fmt.Sprintf(e.msg)
}

type NoRoleSelectedError struct{}

func (e *NoRoleSelectedError) Error() string {
	return "Unable to select role"
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
	if a.Profile != "" {
		cache := ctx.Settings.Cache.GetSSO()
		rFlat, err := cache.Roles.GetRoleByProfile(a.Profile, ctx.Settings)
		if err != nil {
			return &InvalidArgsError{msg: "Invalid --profile %s", arg: a.Profile}
		}

		a.AccountId = rFlat.AccountId
		a.RoleName = rFlat.RoleName

		return nil
	}

	if a.Arn != "" {
		accountId, role, err := utils.ParseRoleARN(a.Arn)
		if err != nil {
			return &InvalidArgsError{msg: "Invalid --arn %s", arg: a.Arn}
		}
		a.AccountId = accountId
		a.RoleName = role

		return nil
	}

	if a.AccountId != 0 && a.RoleName != "" {
		return nil
	} else if a.AccountId != 0 || a.RoleName != "" {
		return &InvalidArgsError{msg: "Must specify both --account and --role"}
	}

	return &NoRoleSelectedError{}
}

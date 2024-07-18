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

	"github.com/synfinatic/aws-sso-cli/internal/sso"
	"github.com/synfinatic/gotable"
)

type ListSSORolesCmd struct{}

// AfterApply determines if SSO auth token is required
func (l ListSSORolesCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_NO
	return nil
}

func (cc *ListSSORolesCmd) Run(ctx *RunContext) error {
	var err error

	var accounts []sso.AccountInfo
	if accounts, err = AwsSSO.GetAccounts(); err != nil {
		return err
	}

	tr := []gotable.TableStruct{}

	for _, account := range accounts {
		log.Debugf("Fetching roles for %s | %s (%s)...", account.AccountName, account.AccountId, account.EmailAddress)
		roles, err := AwsSSO.GetRoles(account)
		log.Debugf("AWS returned %d roles", len(roles))
		if err != nil {
			return nil
		}
		for _, role := range roles {
			tr = append(tr, sso.AWSRoleFlat{
				AccountId:   account.GetAccountId64(),
				AccountName: account.AccountName,
				RoleName:    role.RoleName,
			})
		}
	}

	fields := []string{"AccountId", "AccountName", "RoleName"}
	if err = gotable.GenerateTable(tr, fields); err != nil {
		fmt.Printf("\n")
	}

	return err
}

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
	"sort"

	"github.com/synfinatic/aws-sso-cli/sso"
)

type TagsCmd struct {
	AccountId   int64  `kong:"name='account',short='A',help='Filter results based on AWS AccountID'"`
	Role        string `kong:"short='R',help='Filter results based on AWS Role Name'"`
	ForceUpdate bool   `kong:"help='Force account/role cache update'"`
}

func (cc *TagsCmd) Run(ctx *RunContext) error {
	set := ctx.Settings
	cache := ctx.Settings.Cache.GetSSO()
	if ctx.Cli.Tags.ForceUpdate {
		s := set.SSO[ctx.Cli.SSO]

		ssoName, err := ctx.Settings.GetSelectedSSOName(ctx.Cli.SSO)
		if err != nil {
			log.Fatalf(err.Error())
		}

		err = set.Cache.Refresh(AwsSSO, s, ssoName)
		if err != nil {
			log.WithError(err).Fatalf("Unable to refresh role cache")
		}
		err = set.Cache.Save(true)
		if err != nil {
			log.WithError(err).Errorf("Unable to save cache")
		}
	}
	roles := []*sso.AWSRoleFlat{}

	// If user has specified an account (or account + role) then limit
	if ctx.Cli.Tags.AccountId != 0 {
		for _, fRole := range cache.Roles.GetAccountRoles(ctx.Cli.Tags.AccountId) {
			if ctx.Cli.Tags.Role == "" {
				roles = append(roles, fRole)
			} else {
				if fRole.RoleName == ctx.Cli.Tags.Role {
					roles = append(roles, fRole)
				}
			}
		}
	} else if ctx.Cli.Tags.Role != "" {
		for _, v := range cache.Roles.GetAllRoles() {
			if v.RoleName == ctx.Cli.Tags.Role {
				roles = append(roles, v)
			}
		}
	} else {
		roles = cache.Roles.GetAllRoles()
	}

	for _, fRole := range roles {
		fmt.Printf("%s\n", fRole.Arn)
		keys := make([]string, 0, len(fRole.Tags))
		for k := range fRole.Tags {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %s: %s\n", k, fRole.Tags[k])
		}
		fmt.Printf("\n")
	}
	return nil
}

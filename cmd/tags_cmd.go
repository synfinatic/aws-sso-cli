package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021 Aaron Turner  <synfinatic at gmail dot com>
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

	log "github.com/sirupsen/logrus"
)

type TagsCmd struct {
	AccountId   string `kong:"optional,name='account',short='A',help='Filter regsults based on AWS AccountID',env='AWS_SSO_ACCOUNTID'"`
	Role        string `kong:"optional,name='role',short='R',help='Filter results based on AWS Role Name',env='AWS_SSO_ROLE'"`
	ForceUpdate bool   `kong:"optional,name='force-update',help='Force account/role cache update'"`
}

func (cc *TagsCmd) Run(ctx *RunContext) error {
	sso := ctx.Config.SSO[ctx.Cli.SSO]
	sso.Refresh()

	allRoles := map[string][]RoleInfo{}
	err := ctx.Store.GetRoles(&allRoles)
	if err != nil {
		log.Fatalf("Unable to load roles from cache: %s", err.Error())
	}
	if ctx.Store.GetRolesExpired() {
		log.Warn("Role cache may be out of date")
	}

	if ctx.Cli.Tags.AccountId != "" {
		for a, _ := range allRoles {
			if a != ctx.Cli.Tags.AccountId {
				delete(allRoles, a)
			}
		}
	}

	if ctx.Cli.Tags.Role != "" {
		for account, roles := range allRoles {
			for _, role := range roles {
				if role.RoleName == ctx.Cli.Tags.Role {
					// There can be only one
					allRoles[account] = []RoleInfo{role}
					break
				}
			}

		}
	}

	configRoles := sso.GetRoles()

	for account, roles := range allRoles {
		for _, role := range roles {
			fmt.Printf("%s\n", role.RoleArn())
			fmt.Printf("  AccountId: %s\n", account)
			fmt.Printf("  RoleName: %s\n", role.RoleName)
			// config level tags
			for _, crole := range configRoles {
				if role.RoleArn() == crole.ARN {
					for k, v := range crole.GetAllTags() {
						fmt.Printf("  %s: %s\n", k, v)
					}

					break
				}
			}
			fmt.Printf("\n")
		}
	}
	return nil
}

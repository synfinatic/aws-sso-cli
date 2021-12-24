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
	"github.com/synfinatic/aws-sso-cli/sso"
)

type TagsCmd struct {
	AccountId   int64  `kong:"name='account',short='A',help='Filter results based on AWS AccountID'"`
	Role        string `kong:"short='R',help='Filter results based on AWS Role Name'"`
	ForceUpdate bool   `kong:"help='Force account/role cache update'"`
}

func (cc *TagsCmd) Run(ctx *RunContext) error {
	set := ctx.Settings
	if ctx.Cli.Tags.ForceUpdate {
		s := set.SSO[ctx.Cli.SSO]
		awssso := sso.NewAWSSSO(s, &ctx.Store)
		err := awssso.Authenticate(ctx.Settings.UrlAction, ctx.Settings.Browser)
		if err != nil {
			log.WithError(err).Fatalf("Unable to authenticate")
		}

		err = set.Cache.Refresh(awssso, s)
		if err != nil {
			log.WithError(err).Fatalf("Unable to refresh role cache")
		}
		err = set.Cache.Save(true)
		if err != nil {
			log.WithError(err).Warnf("Unable to save cache")
		}
	} else {
		s, err := ctx.Settings.GetSelectedSSO(ctx.Cli.SSO)
		if err != nil {
			return err
		}

		if err := set.Cache.Expired(s); err != nil {
			log.Warn(err.Error())
		}
	}
	roles := []*sso.AWSRoleFlat{}

	// If user has specified an account (or account + role) then limit
	if ctx.Cli.Tags.AccountId != 0 {
		for _, fRole := range set.Cache.Roles.GetAccountRoles(ctx.Cli.Tags.AccountId) {
			if ctx.Cli.Tags.Role == "" {
				roles = append(roles, fRole)
			} else {
				if fRole.RoleName == ctx.Cli.Tags.Role {
					roles = append(roles, fRole)
				}
			}
		}
	} else if ctx.Cli.Tags.Role != "" {
		for _, v := range set.Cache.Roles.GetAllRoles() {
			if v.RoleName == ctx.Cli.Tags.Role {
				roles = append(roles, v)
			}
		}
	} else {
		roles = set.Cache.Roles.GetAllRoles()
	}

	for _, fRole := range roles {
		fmt.Printf("%s\n", fRole.Arn)
		for k, v := range fRole.Tags {
			fmt.Printf("  %s: %s\n", k, v)
		}
		fmt.Printf("\n")
	}
	return nil
}

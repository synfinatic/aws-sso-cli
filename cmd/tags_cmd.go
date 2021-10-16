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
	AccountId   int64  `kong:"optional,name='account',short='A',default=-1,help='Filter regsults based on AWS AccountID',env='AWS_SSO_ACCOUNTID'"`
	Role        string `kong:"optional,name='role',short='R',help='Filter results based on AWS Role Name',env='AWS_SSO_ROLE'"`
	ForceUpdate bool   `kong:"optional,name='force-update',help='Force account/role cache update'"`
}

func (cc *TagsCmd) Run(ctx *RunContext) error {
	if ctx.Cli.Tags.ForceUpdate {
		s := ctx.Config.SSO[ctx.Cli.SSO]
		awssso := sso.NewAWSSSO(s.SSORegion, s.StartUrl, &ctx.Store)
		err := awssso.Authenticate(ctx.Config.PrintUrl, ctx.Config.Browser)
		if err != nil {
			log.WithError(err).Fatalf("Unable to authenticate")
		}

		err = ctx.Cache.Refresh(awssso, s)
		if err != nil {
			log.WithError(err).Fatalf("Unable to refresh role cache")
		}
		err = ctx.Cache.Save()
		if err != nil {
			log.WithError(err).Warnf("Unable to save cache")
		}
	} else if err := ctx.Cache.Expired(ctx.Config.GetDefaultSSO()); err != nil {
		log.Warn(err.Error())
	}
	roles := []*sso.AWSRoleFlat{}

	// If user has specified an account (or account + role) then limit
	if ctx.Cli.Tags.AccountId != -1 {
		for _, fRole := range ctx.Cache.Roles.GetAccountRoles(ctx.Cli.Tags.AccountId) {
			if ctx.Cli.Tags.Role != "" {
				roles = append(roles, fRole)
			} else {
				if fRole.RoleName == ctx.Cli.Tags.Role {
					roles = append(roles, fRole)
				}
			}
		}
	} else {
		roles = ctx.Cache.Roles.GetAllRoles()
	}

	for _, fRole := range roles {
		fmt.Printf("%s\n  AccountId: %d\n  RoleName: %s\n", fRole.Arn, fRole.AccountId, fRole.RoleName)
		for k, v := range fRole.Tags {
			fmt.Printf("  %s: %s\n", k, v)
		}
		fmt.Printf("\n")
	}
	return nil
}

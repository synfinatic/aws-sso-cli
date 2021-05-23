package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021 Aaron Turner  <aturner at synfin dot net>
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

	//	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
	"github.com/synfinatic/onelogin-aws-role/utils"
)

// Fields match those in FlatConfig.  Used when user doesn't have the `fields` in
// their YAML config file or provided list on the CLI
var defaultListFields = []string{
	"AccountId",
	"AccountName",
	"Role",
	"Profile",
	"Region",
	"Expires",
}

type ListCmd struct {
	Fields      []string `kong:"optional,arg,enum='AccountId,AccountName,Arn,Role,Expires,Profile,Region,SSORegion,StartUrl',help='Fields to display'"`
	ListFields  bool     `kong:"optional,name='list-fields',short='f',help='List available fields'"`
	ForceUpdate bool     `kong:"optional,name='force-update',help='Force cache update'"`
}

// what should this actually do?
func (cc *ListCmd) Run(ctx *RunContext) error {
	var secureStore SecureStorage
	var err error

	if ctx.Cli.Store == "json" {
		secureStore, err = OpenJsonStore(GetPath(ctx.Cli.JsonStore))
		if err != nil {
			log.Panicf("Unable to open JSON Secure store: %s", err)
		}
	} else {
		log.Panicf("SecureStorage '%s' is not yet supported", ctx.Cli.Store)
	}

	roles := map[string][]RoleInfo{}
	err = secureStore.GetRoles(&roles)

	if err != nil || ctx.Cli.List.ForceUpdate {
		roles = map[string][]RoleInfo{} // zero out roles if we are doing a --force-update
		awssso := NewAWSSSO(ctx.Config.Region, ctx.Config.SSORegion, ctx.Config.StartUrl, &secureStore)
		err = awssso.Authenticate(ctx.Cli.PrintUrl, ctx.Cli.Browser)
		if err != nil {
			log.WithError(err).Panicf("Unable to authenticate")
		}

		accounts, err := awssso.GetAccounts()
		if err != nil {
			log.WithError(err).Panicf("Unable to get accounts")
		}

		for _, a := range accounts {
			account := a.AccountId
			roleInfo, err := awssso.GetRoles(a)
			if err != nil {
				log.WithError(err).Panicf("Unable to get roles for AccountId: %s", account)
			}

			for _, r := range roleInfo {
				roles[account] = append(roles[account], r)
			}
		}
		secureStore.SaveRoles(roles)
	} else {
		log.Info("Using cache.  Use --force-update to force a cache update.")
	}

	printRoles(roles)

	return nil
}

func printRoles(roles map[string][]RoleInfo) {
	tr := []utils.TableStruct{}
	idx := 0
	for _, roleInfo := range roles {
		for _, role := range roleInfo {
			role.Idx = idx
			idx += 1
			tr = append(tr, role)
		}
	}

	utils.GenerateTable(tr, []string{"Idx", "RoleName", "AccountId", "AccountName", "EmailAddress"})
	fmt.Printf("\n")
}

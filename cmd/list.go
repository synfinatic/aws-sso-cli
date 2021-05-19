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
	Fields     []string `kong:"optional,arg,enum='AccountId,AccountName,Arn,Role,Expires,Profile,Region,SSORegion,StartUrl',help='Fields to display'"`
	ListFields bool     `kong:"optional,short='f',help='List available fields'"`
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

	awssso := NewAWSSSO(ctx.Config.Region, ctx.Config.SSORegion, ctx.Config.StartUrl, &secureStore)
	err = awssso.RegisterClient()
	if err != nil {
		log.WithError(err).Panicf("Unable to RegisterClient")
	}

	err = awssso.StartDeviceAuthorization()
	if err != nil {
		log.WithError(err).Panicf("Unable to StartDeviceAuth")
	}

	auth, err := awssso.GetDeviceAuthInfo()
	if err != nil {
		log.WithError(err).Panicf("Unable to get DeviceAuthInfo")
	}

	fmt.Printf(`Please open the following URL in your browser:

	%s

`, auth.VerificationUriComplete)
	log.Debugf("Waiting for SSO authentication")

	err = awssso.CreateToken()
	if err != nil {
		log.WithError(err).Panicf("Unable to get AWS SSO Token")
	}

	fmt.Printf("\n\nThe following accounts are authorized:\n")
	accounts, err := awssso.GetAccounts()
	if err != nil {
		log.WithError(err).Panicf("Unable to get accounts")
	}

	tr := []utils.TableStruct{}
	for _, a := range accounts {
		tr = append(tr, a)
	}
	utils.GenerateTable(tr, []string{"Idx", "AccountId", "AccountName", "EmailAddress"})
	fmt.Printf("\n")

	/*
		fmt.Printf("The following roles are authorized:\n")
		roles, err := awssso.GetRoles()
		if err != nil {
			log.WithError(err).Panicf("Unable to get roles")
		}

		for _, r := range roles {
			fmt.Printf("%d %s\n", r.AccountId, r.RoleName)
		}
		fmt.Printf("\n")
	*/
	return nil
}

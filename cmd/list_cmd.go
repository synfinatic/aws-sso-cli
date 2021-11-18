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
	"reflect"
	"sort"

	log "github.com/sirupsen/logrus"
	"github.com/synfinatic/aws-sso-cli/utils"
	"github.com/synfinatic/gotable"
)

// keys match AWSRoleFlat header and value is the description
var allListFields = map[string]string{
	"Id":           "Column Index",
	"Arn":          "AWS Role Resource Name",
	"AccountId":    "AWS AccountID",
	"AccountName":  "Configured Account Name",
	"AccountAlias": "AWS Account Alias",
	"EmailAddress": "Root email for AWS account",
	"ExpiresStr":   "Time until STS creds expire",
	"Expires":      "Unix Epoch when STS creds expire",
	//	"Profile":       "AWS_PROFILE",
	"RoleName": "AWS Role Name",
	//	"Via":           "Role Chain Via",
}

type ListCmd struct {
	ListFields bool     `kong:"optional,short='f',help='List available fields',xor='fields'"`
	Fields     []string `kong:"optional,arg,help='Fields to display',env='AWS_SSO_FIELDS',predictor='fieldList',xor='fields'"`
}

// what should this actually do?
func (cc *ListCmd) Run(ctx *RunContext) error {
	var err error

	// If `-f` then print our fields and exit
	if ctx.Cli.List.ListFields {
		listAllFields()
		return nil
	}

	s, err := ctx.Settings.GetSelectedSSO(ctx.Cli.SSO)
	if err != nil {
		return err
	}
	if err = ctx.Settings.Cache.Expired(s); err != nil {
		c := &CacheCmd{}
		if err = c.Run(ctx); err != nil {
			log.WithError(err).Errorf("Unable to refresh local cache")
		}
	}

	fields := ctx.Settings.ListFields
	if len(ctx.Cli.List.Fields) > 0 {
		fields = ctx.Cli.List.Fields
	}

	printRoles(ctx, fields)

	return nil
}

// DefaultCmd has no args, and just prints the default fields and exists because
// as of Kong 0.2.18 you can't have a default command which takes args
type DefaultCmd struct{}

func (cc *DefaultCmd) Run(ctx *RunContext) error {
	printRoles(ctx, ctx.Settings.ListFields)
	return nil
}

// Print all our roles
func printRoles(ctx *RunContext, fields []string) {
	roles := ctx.Settings.Cache.Roles
	tr := []gotable.TableStruct{}
	idx := 0

	// print in AccountId order
	accounts := []int64{}
	for account := range roles.Accounts {
		accounts = append(accounts, account)
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i] < accounts[j] })

	for _, account := range accounts {
		// print roles in order
		roleNames := []string{}
		for _, roleFlat := range roles.GetAccountRoles(account) {
			roleNames = append(roleNames, roleFlat.RoleName)
		}
		sort.Strings(roleNames)

		for _, roleName := range roleNames {
			roleFlat, _ := roles.GetRole(account, roleName)
			if !roleFlat.IsExpired() {
				if exp, err := utils.TimeRemain(roleFlat.Expires, true); err == nil {
					roleFlat.ExpiresStr = exp
				}
			}
			roleFlat.Id = idx
			idx += 1
			tr = append(tr, *roleFlat)
		}
	}

	if err := gotable.GenerateTable(tr, fields); err != nil {
		log.WithError(err).Fatalf("Unable to generate report")
	}
	fmt.Printf("\n")
}

// Code to --list-fields
type ConfigFieldNames struct {
	Field       string `header:"Field"`
	Description string `header:"Description"`
}

// GetHeader is required for GenerateTable()
func (cfn ConfigFieldNames) GetHeader(fieldName string) (string, error) {
	v := reflect.ValueOf(cfn)
	return gotable.GetHeaderTag(v, fieldName)
}

// listAllFields generates a table with all the AWSRoleFlat fields we can print
func listAllFields() {
	names := []string{}
	for k := range allListFields {
		names = append(names, k)
	}
	sort.Strings(names)
	ts := []gotable.TableStruct{}
	for _, k := range names {
		ts = append(ts, ConfigFieldNames{
			Field:       k,
			Description: allListFields[k],
		})
	}

	fields := []string{"Field", "Description"}
	if err := gotable.GenerateTable(ts, fields); err != nil {
		log.WithError(err).Fatalf("Unable to generate report")
	}
	fmt.Printf("\n")
}

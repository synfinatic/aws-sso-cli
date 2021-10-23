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
	"github.com/synfinatic/aws-sso-cli/sso"
	"github.com/synfinatic/gotable"
)

// Fields match those in AWSRoleFlat.  Used when user doesn't have the `fields` in
// their YAML config file or provided list on the CLI
var defaultListFields = []string{
	"AccountId",
	"AccountName",
	"RoleName",
	"Expires",
}

// keys match AWSRoleFlat header and value is the description
var allListFields = map[string]string{
	"Id":            "Column Index",
	"Arn":           "AWS Role Resource Name",
	"AccountId":     "AWS AccountID",
	"AccountName":   "AWS AccountName",
	"DefaultRegion": "Default AWS Region",
	"EmailAddress":  "Root Email",
	"Expires":       "Creds Expire",
	"Profile":       "AWS_PROFILE",
	"RoleName":      "AWS Role",
	"Via":           "Role Chain Via",
}

type ListCmd struct {
	Fields     []string `kong:"optional,arg,enum='AccountId,AccountName,Arn,EmailAddress,Expires,Id,Profile,RoleName',help='Fields to display',env='AWS_SSO_FIELDS'"`
	ListFields bool     `kong:"optional,name='list-fields',short='f',help='List available fields'"`
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

	fields := defaultListFields
	if len(ctx.Cli.List.Fields) > 0 {
		fields = ctx.Cli.List.Fields
	}

	printRoles(ctx.Settings.Cache.Roles, fields)

	return nil
}

// Print all our roles
func printRoles(roles *sso.Roles, fields []string) {
	tr := []gotable.TableStruct{}
	idx := 0

	// print in AccountId order
	accounts := []int64{}
	for account, _ := range roles.Accounts {
		accounts = append(accounts, account)
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i] < accounts[j] })

	for _, account := range accounts {
		for _, role := range roles.GetAccountRoles(account) {
			role.Id = idx
			idx += 1
			tr = append(tr, *role)
		}
	}

	gotable.GenerateTable(tr, fields)
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
	ts := []gotable.TableStruct{}
	for k, v := range allListFields {
		ts = append(ts, ConfigFieldNames{
			Field:       k,
			Description: v,
		})
	}

	fields := []string{"Field", "Description"}
	gotable.GenerateTable(ts, fields)
	fmt.Printf("\n")
}

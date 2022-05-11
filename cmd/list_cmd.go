package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2022 Aaron Turner  <synfinatic at gmail dot com>
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
	"strings"

	"github.com/synfinatic/aws-sso-cli/internal/predictor"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
	"github.com/synfinatic/aws-sso-cli/sso"
	"github.com/synfinatic/aws-sso-cli/storage"
	"github.com/synfinatic/gotable"
)

type ListCmd struct {
	ListFields bool     `kong:"short='f',help='List available fields',xor='fields'"`
	CSV        bool     `kong:"help='Generate CSV instead of a table',xor='fields'"`
	Prefix     string   `kong:"short='P',help='Filter based on the <FieldName>=<Prefix>'"`
	Fields     []string `kong:"optional,arg,help='Fields to display',env='AWS_SSO_FIELDS',predictor='fieldList',xor='fields'"`
}

// what should this actually do?
func (cc *ListCmd) Run(ctx *RunContext) error {
	var err error
	var prefixSearch []string

	// If `-f` then print our fields and exit
	if ctx.Cli.List.ListFields {
		listAllFields()
		return nil
	}

	if ctx.Cli.List.Prefix != "" {
		if !strings.Contains(ctx.Cli.List.Prefix, "=") {
			return fmt.Errorf("--prefix must be in the format of <FieldName>=<Prefix>")
		}
		prefixSearch = strings.Split(ctx.Cli.List.Prefix, "=")
		validFields := make([]string, len(predictor.AllListFields))
		i := 0
		for k := range predictor.AllListFields {
			validFields[i] = k
			i++
		}
		if !utils.StrListContains(prefixSearch[0], validFields) {
			return fmt.Errorf("--prefix <FieldName> must be a valid field: %s", prefixSearch[0])
		}
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

	return printRoles(ctx, fields, ctx.Cli.List.CSV, prefixSearch)
}

// DefaultCmd has no args, and just prints the default fields and exists because
// as of Kong 0.2.18 you can't have a default command which takes args
type DefaultCmd struct{}

func (cc *DefaultCmd) Run(ctx *RunContext) error {
	s, err := ctx.Settings.GetSelectedSSO("")
	if err != nil {
		return err
	}

	// update cache?
	if err = ctx.Settings.Cache.Expired(s); err != nil {
		c := &CacheCmd{}
		if err = c.Run(ctx); err != nil {
			log.WithError(err).Errorf("Unable to refresh local cache")
		}
	}

	return printRoles(ctx, ctx.Settings.ListFields, false, []string{})
}

// Print all our roles
func printRoles(ctx *RunContext, fields []string, csv bool, prefixSearch []string) error {
	var err error
	roles := ctx.Settings.Cache.GetSSO().Roles
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
			// update Profile
			p, err := roleFlat.ProfileName(ctx.Settings)
			if err == nil {
				roleFlat.Profile = p
			}

			if len(prefixSearch) > 0 {
				match, err := roleFlat.HasPrefix(prefixSearch[0], prefixSearch[1])
				if err != nil {
					return err
				}

				if !match {
					// skip because not a match
					continue
				}
			}

			roleFlat.Id = idx
			idx += 1
			tr = append(tr, *roleFlat)
		}
	}

	// Determine when our AWS SSO session expires
	// list doesn't call doAuth() so we have to initialize our global *AwsSSO manually
	s, err := ctx.Settings.GetSelectedSSO(ctx.Cli.SSO)
	if err != nil {
		log.Fatalf("%s", err.Error())
	}
	AwsSSO = sso.NewAWSSSO(s, &ctx.Store)

	if csv {
		err = gotable.GenerateCSV(tr, fields)
	} else {
		expires := ""
		ctr := storage.CreateTokenResponse{}
		if err := ctx.Store.GetCreateTokenResponse(AwsSSO.StoreKey(), &ctr); err != nil {
			log.Debugf("Unable to get SSO session expire time: %s", err.Error())
		} else {
			if exp, err := utils.TimeRemain(ctr.ExpiresAt, true); err != nil {
				log.Errorf("Unable to determine time remain for %d: %s", ctr.ExpiresAt, err)
			} else {
				expires = fmt.Sprintf(" [Expires in: %s]", exp)
			}
		}
		fmt.Printf("List of AWS roles for SSO Instance: %s%s\n\n", ctx.Settings.DefaultSSO, expires)

		err = gotable.GenerateTable(tr, fields)
	}
	if err == nil {
		fmt.Printf("\n")
	}
	return err
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
	for k := range predictor.AllListFields {
		names = append(names, k)
	}
	sort.Strings(names)
	ts := []gotable.TableStruct{}
	for _, k := range names {
		ts = append(ts, ConfigFieldNames{
			Field:       k,
			Description: predictor.AllListFields[k],
		})
	}

	fields := []string{"Field", "Description"}
	if err := gotable.GenerateTable(ts, fields); err != nil {
		log.WithError(err).Fatalf("Unable to generate report")
	}
	fmt.Printf("\n")
}

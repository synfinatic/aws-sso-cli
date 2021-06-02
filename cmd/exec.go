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
	"os"
	"os/exec"
	"strconv"

	"github.com/Songmu/prompter"
	log "github.com/sirupsen/logrus"
)

type ExecCmd struct {
	Fields []string `kong:"optional,enum='Id,AccountId,AccountName,EmailAddress,RoleName,Expires,Profile',help='Fields to display',env='AWS_SSO_FIELDS'"`
	Cmd    string   `kong:"arg,optional,name='command',help='Command to execute',env='SHELL'"`
	Args   []string `kong:"arg,optional,name='args',help='Associated arguments for the command'"`
}

func (cc *ExecCmd) Run(ctx *RunContext) error {
	var err error

	roles := map[string][]RoleInfo{}
	err = ctx.Store.GetRoles(&roles)

	fields := defaultListFields
	if len(ctx.Cli.Exec.Fields) > 0 {
		fields = ctx.Cli.Exec.Fields
	}
	table := printRoles(roles, fields)
	var roleid string
	for len(roleid) == 0 {
		roleid = prompter.Prompt("Select Role Id", "")
	}
	log.Debugf("Role %s selected", roleid)

	awssso := NewAWSSSO(ctx.Sso.SSORegion, ctx.Sso.StartUrl, &ctx.Store)
	err = awssso.Authenticate(ctx.Cli.PrintUrl, ctx.Cli.Browser)
	if err != nil {
		log.WithError(err).Fatalf("Unable to authenticate")
	}

	tableid, err := strconv.Atoi(roleid)
	if err != nil {
		log.Fatalf("Invalid Role Id: %s", roleid)
	} else if tableid < 0 || tableid > len(table) {
		log.Fatalf("Role Id is outside of valid range")
	}
	creds, err := awssso.GetRoleCredentials(table[tableid].AccountId, table[tableid].RoleName)
	if err != nil {
		log.WithError(err).Fatalf("Unable to get role credentials for %s", roleid)
	}

	// set our ENV & execute the command
	os.Setenv("AWS_ACCESS_KEY_ID", creds.AccessKeyId)
	os.Setenv("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)
	os.Setenv("AWS_SESSION_TOKEN", creds.SessionToken)
	os.Setenv("AWS_ACCOUNT_ID", creds.AccountId)
	os.Setenv("AWS_ROLE_NAME", creds.RoleName)
	if ctx.Cli.Region != "" {
		os.Setenv("AWS_DEFAULT_REGION", ctx.Cli.Region)
	}
	os.Setenv("AWS_SESSION_EXPIRATION", creds.ExpireString())
	//	os.Setenv("AWS_ENABLED_PROFILE", cli.Exec.Profile)
	os.Setenv("AWS_ROLE_ARN", creds.RoleArn())

	// ready our command and connect everything up
	cmd := exec.Command(ctx.Cli.Exec.Cmd, ctx.Cli.Exec.Args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin

	// just do it!
	return cmd.Run()
}

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
	"os"
	"os/exec"
	"strings"

	"github.com/c-bata/go-prompt"
	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
)

type ExecCmd struct {
	Fields    []string `kong:"optional,help='Fields to display',enum='Id,AccountId,AccountName,EmailAddress,RoleName,Expires,Profile',env='AWS_SSO_FIELDS'"`
	Arn       string   `kong:"optional,name='arn',short='a',help='ARN of role to assume',env='AWS_SSO_ROLE_ARN'"`
	AccountId string   `kong:"optional,name='account',short='A',help='AWS AccountID of role to assume',env='AWS_SSO_ACCOUNTID'"`
	Role      string   `kong:"optional,name='role',short='R',help='Name of AWS Role to assume',env='AWS_SSO_ROLE'"`
	Cmd       string   `kong:"arg,optional,name='command',help='Command to execute',env='SHELL'"`
	Args      []string `kong:"arg,optional,name='args',help='Associated arguments for the command'"`
}

func (cc *ExecCmd) Run(ctx *RunContext) error {
	// Did user specify the ARN or account/role?
	if ctx.Cli.Exec.Arn != "" {
		awssso := doAuth(ctx)
		s := strings.Split(ctx.Cli.Exec.Arn, ":")
		if len(s) == 2 {
			// short account:Role format
			return execCmd(ctx, awssso, s[0], s[1])
		}
		// long format for arn:aws:iam:XXXXXXXXXX:role/YYYYYYYY
		accountid := s[3]
		s = strings.Split(s[4], "/")
		role := s[1]
		return execCmd(ctx, awssso, accountid, role)
	} else if ctx.Cli.Exec.AccountId != "" || ctx.Cli.Exec.Role != "" {
		if ctx.Cli.Exec.AccountId == "" || ctx.Cli.Exec.Role == "" {
			return fmt.Errorf("Please specify both --account and --role")
		}
		awssso := doAuth(ctx)
		return execCmd(ctx, awssso, ctx.Cli.Exec.AccountId, ctx.Cli.Exec.Role)
	}

	// use completer to figure out the role
	sso := ctx.Config.SSO[ctx.Cli.SSO]
	sso.Refresh()
	log.Debugf("sso: %s", spew.Sdump(sso))
	c := NewTagsCompleter(ctx, sso)
	p := prompt.New(
		c.Executor,
		c.Complete,
		prompt.OptionPrefix(">>> "),
		prompt.OptionSetExitCheckerOnInput(c.ExitChecker),
	)
	p.Run()
	return nil
}

func doAuth(ctx *RunContext) *AWSSSO {
	sso := ctx.Config.SSO[ctx.Cli.SSO]
	awssso := NewAWSSSO(sso.SSORegion, sso.StartUrl, &ctx.Store)
	err := awssso.Authenticate(ctx.Cli.PrintUrl, ctx.Cli.Browser)
	if err != nil {
		log.WithError(err).Fatalf("Unable to authenticate")
	}
	return awssso
}

func execCmd(ctx *RunContext, awssso *AWSSSO, accountid, role string) error {
	creds, err := awssso.GetRoleCredentials(accountid, role)
	if err != nil {
		log.WithError(err).Fatalf("Unable to get role credentials for %s", role)
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
	//	os.Setenv("AWS_SSO_PROFILE", cli.Exec.Profile)
	os.Setenv("AWS_ROLE_ARN", creds.RoleArn())

	// ready our command and connect everything up
	cmd := exec.Command(ctx.Cli.Exec.Cmd, ctx.Cli.Exec.Args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin

	// just do it!
	return cmd.Run()
}

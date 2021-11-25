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
	"strings"

	// log "github.com/sirupsen/logrus"
	"github.com/synfinatic/aws-sso-cli/utils"
)

type EvalCmd struct {
	// AWS Params
	Arn       string `kong:"short='a',help='ARN of role to assume',predictor='arn'"`
	AccountId int64  `kong:"name='account',short='A',help='AWS AccountID of role to assume',predictor='accountId'"`
	Role      string `kong:"short='R',help='Name of AWS Role to assume',predictor='role'"`

	Clear    bool   `kong:"short='c',help='Generate \"unset XXXX\" commands to clear environment'"`
	NoRegion bool   `kong:"short='n',help='Do not set/clear AWS_DEFAULT_REGION from config.yaml'"`
	Refresh  bool   `kong:"short='r',help='Refresh current IAM credentials'"`
	EnvArn   string `kong:"hidden,env='AWS_SSO_ROLE_ARN'"` // used for refresh
}

func (cc *EvalCmd) Run(ctx *RunContext) error {
	var err error

	if ctx.Cli.Eval.Clear {
		unsetEnvVars(ctx)
		return nil
	}

	// never print the URL since that breaks bash's eval
	if ctx.Settings.UrlAction == "print" {
		ctx.Settings.UrlAction = "open"
	}

	var role string
	var accountid int64

	// refreshing?
	if ctx.Cli.Eval.Refresh {
		if len(ctx.Cli.Eval.EnvArn) == 0 {
			return fmt.Errorf("Unable to determine current IAM role")
		}
		accountid, role, err = utils.ParseRoleARN(ctx.Cli.Eval.EnvArn)
		if err != nil {
			return err
		}
	} else if len(ctx.Cli.Eval.Arn) > 0 {
		accountid, role, err = utils.ParseRoleARN(ctx.Cli.Eval.Arn)
		if err != nil {
			return err
		}
	} else if len(ctx.Cli.Eval.Role) > 0 && ctx.Cli.Eval.AccountId > 0 {
		// if CLI args are speecified, use that
		role = ctx.Cli.Eval.Role
		accountid = ctx.Cli.Eval.AccountId
	} else {
		return fmt.Errorf("Please specify --refresh, --arn, or --account and --role")
	}
	region := ctx.Settings.GetDefaultRegion(accountid, role, ctx.Cli.Eval.NoRegion)

	awssso := doAuth(ctx)
	for k, v := range execShellEnvs(ctx, awssso, accountid, role, region) {
		if len(v) == 0 {
			fmt.Printf("unset %s\n", k)
		} else if strings.Contains(v, " ") {
			fmt.Printf("export %s=\"%s\"\n", k, v)
		} else {
			fmt.Printf("export %s=%s\n", k, v)
		}
	}
	return nil
}

func unsetEnvVars(ctx *RunContext) {
	envs := []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"AWS_SSO_ACCOUNT_ID",
		"AWS_SSO_ROLE_NAME",
		"AWS_SSO_ROLE_ARN",
		"AWS_SSO_SESSION_EXPIRATION",
		"AWS_SSO_PROFILE",
	}

	// clear the region if
	// 1. User did not specify --no-region AND
	// 2. The AWS_DEFAULT_REGION is managed by us (tracks AWS_SSO_DEFAULT_REGION)
	if !ctx.Cli.Eval.NoRegion && os.Getenv("AWS_DEFAULT_REGION") == os.Getenv("AWS_SSO_DEFAULT_REGION") {
		envs = append(envs, "AWS_DEFAULT_REGION")
		envs = append(envs, "AWS_SSO_DEFAULT_REGION")
	} else if os.Getenv("AWS_DEFAULT_REGION") != os.Getenv("AWS_SSO_DEFAULT_REGION") {
		// clear the tracking variable if we don't match
		envs = append(envs, "AWS_SSO_DEFAULT_REGION")
	}

	for _, e := range envs {
		fmt.Printf("unset %s\n", e)
	}
}

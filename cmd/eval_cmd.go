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
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/synfinatic/aws-sso-cli/utils"
)

type EvalCmd struct {
	// AWS Params
	Duration  int64  `kong:"short='d',help='AWS Session duration in minutes (default 60)',default=60,env='AWS_SSO_DURATION'"`
	Arn       string `kong:"short='a',help='ARN of role to assume',env='AWS_SSO_ROLE_ARN',predictor='arn',xor='arn-1',xor='arn-2'"`
	AccountId int64  `kong:"name='account',short='A',help='AWS AccountID of role to assume',env='AWS_SSO_ACCOUNTID',predictor='accountId',xor='arn-1'"`
	Role      string `kong:"short='R',help='Name of AWS Role to assume',env='AWS_ROLE_NAME',predictor='role',xor='arn-2'"`
	Clear     bool   `kong:"short='c',help='Generate \"unset XXXX\" commands to clear environment'"`
	NoRegion  bool   `kong:"help='Do not set/clear AWS_DEFAULT_REGION from config'"`
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

	// if CLI args are speecified, use that
	role := ctx.Cli.Eval.Role
	account := ctx.Cli.Eval.AccountId
	region := ctx.Settings.GetDefaultRegion(account, role, false)

	if len(ctx.Cli.Eval.Arn) > 0 {
		account, role, err = utils.ParseRoleARN(ctx.Cli.Eval.Arn)
		if err != nil {
			return err
		}
	}

	// Fall back to ENV vars
	if len(role) == 0 || account == 0 {
		accountid := os.Getenv("AWS_ACCOUNT_ID")
		role = os.Getenv("AWS_ROLE_NAME")
		if len(accountid) == 0 || len(role) == 0 {
			return fmt.Errorf("Please specify --arn or --account and --role")
		}

		account, err = strconv.ParseInt(accountid, 10, 64)
		if err != nil {
			return fmt.Errorf("Unable to parse AWS_ACCOUNT_ID = %s: %s", accountid, err.Error())
		}
		log.Infof("Refreshing current AWS Role credentials")
	}

	awssso := doAuth(ctx)
	for k, v := range execShellEnvs(ctx, awssso, account, role, region) {
		if strings.Contains(v, " ") {
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
		"AWS_ACCOUNT_ID",
		"AWS_ROLE_NAME",
		"AWS_ROLE_ARN",
		"AWS_SESSION_EXPIRATION",
		"AWS_SSO_PROFILE",
	}

	// clear the region if
	// 1. User did not specify --no-region AND
	// 2. The AWS_DEFAULT_REGION is managed by us (tracks AWS_SSO_DEFAULT_REGION)
	if !ctx.Cli.Eval.NoRegion && os.Getenv("AWS_DEFAULT_REGION") == os.Getenv("AWS_SSO_DEFAULT_REGION") {
		envs = append(envs, "AWS_DEFAULT_REGION")
		envs = append(envs, "AWS_SSO_DEFAULT_REGION")
	}

	for _, e := range envs {
		fmt.Printf("unset %s\n", e)
	}
}

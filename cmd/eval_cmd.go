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
	Region    string `kong:"help='AWS Region',env='AWS_DEFAULT_REGION',predictor='region'"`
	Duration  int64  `kong:"short='d',help='AWS Session duration in minutes (default 60)',default=60,env='AWS_SSO_DURATION'"`
	Arn       string `kong:"short='a',help='ARN of role to assume',env='AWS_SSO_ROLE_ARN',predictor='arn',xor='arn-1',xor='arn-2'"`
	AccountId int64  `kong:"name='account',short='A',help='AWS AccountID of role to assume',env='AWS_SSO_ACCOUNTID',predictor='accountId',xor='arn-1'"`
	Role      string `kong:"short='R',help='Name of AWS Role to assume',env='AWS_ROLE_NAME',predictor='role',xor='arn-2'"`
}

func (cc *EvalCmd) Run(ctx *RunContext) error {
	var err error

	// if CLI args are speecified, use that
	role := ctx.Cli.Eval.Role
	account := ctx.Cli.Eval.AccountId
	region := ctx.Cli.Eval.Region

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
			fmt.Printf("Please specify --arn or --account and --role")
		}

		account, err = strconv.ParseInt(accountid, 10, 64)
		if err != nil {
			return fmt.Errorf("Unable to parse AWS_ACCOUNT_ID = %s: %s", accountid, err.Error())
		}
		log.Infof("Refreshing current AWS Role credentials")
	}

	if len(region) == 0 {
		region = ctx.Settings.GetDefaultRegion(account, role)
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

package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2025 Aaron Turner  <synfinatic at gmail dot com>
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
	"encoding/json"
	"fmt"

	// log "github.com/sirupsen/logrus"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

type ProcessCmd struct {
	// AWS Params
	Arn        string `kong:"short='a',help='ARN of role to assume',xor='arn-1',xor='arn-2',predictor='arn'"`
	AccountId  int64  `kong:"name='account',short='A',help='AWS AccountID of role to assume',xor='arn-1',predictor='accountId'"`
	Role       string `kong:"short='R',help='Name of AWS Role to assume',xor='arn-2',predictor='role'"`
	Profile    string `kong:"short='p',help='Name of AWS Profile to assume',xor='arn-1',xor='arn-2',predictor='profile'"`
	STSRefresh bool   `kong:"help='Force refresh of STS Token Credentials'"`
}

// AfterApply list command requires a valid SSO auth token
func (p ProcessCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_REQUIRED
	return nil
}

func (cc *ProcessCmd) Run(ctx *RunContext) error {
	var err error

	role := ctx.Cli.Process.Role
	account := ctx.Cli.Process.AccountId

	if ctx.Cli.Process.Profile != "" {
		cache := ctx.Settings.Cache.GetSSO()
		rFlat, err := cache.Roles.GetRoleByProfile(ctx.Cli.Process.Profile, ctx.Settings)
		if err != nil {
			return err
		}

		role = rFlat.RoleName
		account = rFlat.AccountId
	} else if ctx.Cli.Process.Arn != "" {
		account, role, err = utils.ParseRoleARN(ctx.Cli.Process.Arn)
		if err != nil {
			return err
		}
	}

	if role == "" || account == 0 {
		return fmt.Errorf("please specify --arn or --account and --role")
	}

	return credentialProcess(ctx, account, role)
}

type CredentialProcessOutput struct {
	Version         int
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      string // ISO8601
}

func NewCredentialsProcessOutput(creds *storage.RoleCredentials) *CredentialProcessOutput {
	x := *creds
	c := CredentialProcessOutput{
		Version:         1,
		AccessKeyId:     x.AccessKeyId,
		SecretAccessKey: x.SecretAccessKey,
		SessionToken:    x.SessionToken,
		Expiration:      x.ExpireString(),
	}
	return &c
}

func (cpo *CredentialProcessOutput) Output() (string, error) {
	b, err := json.Marshal(cpo)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func credentialProcess(ctx *RunContext, accountId int64, role string) error {
	creds := GetRoleCredentials(ctx, AwsSSO, ctx.Cli.Process.STSRefresh, accountId, role)

	cpo := NewCredentialsProcessOutput(creds)
	out, err := cpo.Output()
	if err != nil {
		return err
	}
	fmt.Printf("%s", out)
	return nil
}

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
	"encoding/json"
	"fmt"

	// log "github.com/sirupsen/logrus"
	"github.com/synfinatic/aws-sso-cli/sso"
	"github.com/synfinatic/aws-sso-cli/storage"
	"github.com/synfinatic/aws-sso-cli/utils"
)

type ProcessCmd struct {
	// AWS Params
	Arn       string `kong:"short='a',help='ARN of role to assume',xor='arn-1',xor='arn-2',predictor='arn'"`
	AccountId int64  `kong:"name='account',short='A',help='AWS AccountID of role to assume',xor='arn-1',predictor='accountId'"`
	Role      string `kong:"short='R',help='Name of AWS Role to assume',xor='arn-2',predictor='role'"`
}

func (cc *ProcessCmd) Run(ctx *RunContext) error {
	var err error

	if ctx.Settings.UrlAction == "print" {
		return fmt.Errorf("Unsupported --url-action=print option")
	}

	role := ctx.Cli.Process.Role
	account := ctx.Cli.Process.AccountId

	if len(ctx.Cli.Process.Arn) > 0 {
		account, role, err = utils.ParseRoleARN(ctx.Cli.Process.Arn)
		if err != nil {
			return err
		}
	}

	if len(role) == 0 || account == 0 {
		return fmt.Errorf("Please specify --arn or --account and --role")
	}

	awssso := doAuth(ctx)
	return credentialProcess(ctx, awssso, account, role)
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
		Expiration:      x.ExpireISO8601(),
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

func credentialProcess(ctx *RunContext, awssso *sso.AWSSSO, accountId int64, role string) error {
	creds := GetRoleCredentials(ctx, awssso, accountId, role)

	cpo := NewCredentialsProcessOutput(creds)
	out, err := cpo.Output()
	if err != nil {
		return err
	}
	fmt.Printf("%s", out)
	return nil
}

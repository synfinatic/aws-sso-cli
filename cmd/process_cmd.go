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
	"encoding/json"
	"fmt"
	"time"

	//log "github.com/sirupsen/logrus"
	"github.com/synfinatic/aws-sso-cli/sso"
	"github.com/synfinatic/aws-sso-cli/storage"
	"github.com/synfinatic/aws-sso-cli/utils"
)

type ProcessCmd struct {
	// AWS Params
	Duration  int64  `kong:"short='d',help='AWS Session duration in minutes (default 60)',default=60,env='AWS_SSO_DURATION'"`
	Arn       string `kong:"short='a',help='ARN of role to assume',xor='arn-1',xor='arn-2'"`
	AccountId int64  `kong:"name='account',short='A',help='AWS AccountID of role to assume',xor='arn-1'"`
	Role      string `kong:"short='R',help='Name of AWS Role to assume',xor='arn-2'"`
}

func (cc *ProcessCmd) Run(ctx *RunContext) error {
	var err error

	// never print the URL since that breaks AWS's eval
	if ctx.Settings.UrlAction == "print" {
		ctx.Settings.UrlAction = "open"
	}

	role := ctx.Cli.Process.Role
	account := ctx.Cli.Process.AccountId

	if len(ctx.Cli.Process.Arn) > 0 {
		account, role, err = utils.ParseRoleARN(ctx.Cli.Process.Arn)
		if err != nil {
			return err
		}
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
	c := CredentialProcessOutput{
		Version:         1,
		AccessKeyId:     (*creds).AccessKeyId,
		SecretAccessKey: (*creds).SecretAccessKey,
		SessionToken:    (*creds).SessionToken,
		Expiration:      time.Unix((*creds).ExpireEpoch(), 0).Format(time.RFC3339),
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

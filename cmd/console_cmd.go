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
	"io"
	"net/http"
	"net/url"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/c-bata/go-prompt"
	log "github.com/sirupsen/logrus"
	"github.com/synfinatic/aws-sso-cli/sso"
	"github.com/synfinatic/aws-sso-cli/storage"
	"github.com/synfinatic/aws-sso-cli/utils"
)

const AWS_FEDERATED_URL = "https://signin.aws.amazon.com/federation"

type ConsoleCmd struct {
	// Console actually should honor the --region flag
	Region   string `kong:"help='AWS Region',env='AWS_DEFAULT_REGION',predictor='region'"`
	Duration int64  `kong:"short='d',help='AWS Session duration in minutes (default 60)'"` // default stored in DEFAULT_CONFIG
	Prompt   bool   `kong:"short='p',help='Force interactive prompt to select role'"`

	Arn       string `kong:"short='a',help='ARN of role to assume',env='AWS_SSO_ROLE_ARN',predictor='arn'"`
	AccountId int64  `kong:"name='account',short='A',help='AWS AccountID of role to assume',env='AWS_SSO_ACCOUNT_ID',predictor='accountId'"`
	Role      string `kong:"short='R',help='Name of AWS Role to assume',env='AWS_SSO_ROLE_NAME',predictor='role'"`

	AccessKeyId     string `kong:"env='AWS_ACCESS_KEY_ID',hidden"`
	SecretAccessKey string `kong:"env='AWS_SECRET_ACCESS_KEY',hidden"`
	SessionToken    string `kong:"env='AWS_SESSION_TOKEN',hidden"`
}

func (cc *ConsoleCmd) Run(ctx *RunContext) error {
	duration := ctx.Settings.ConsoleDuration
	if ctx.Cli.Console.Duration > 0 {
		duration = ctx.Cli.Console.Duration
	}

	if ctx.Cli.Console.Prompt {
		return consolePrompt(ctx)
	} else if ctx.Cli.Console.Arn != "" {
		awssso := doAuth(ctx)

		accountid, role, err := utils.ParseRoleARN(ctx.Cli.Console.Arn)
		if err != nil {
			return err
		}

		return openConsole(ctx, awssso, accountid, role)
	} else if ctx.Cli.Console.AccountId > 0 && ctx.Cli.Console.Role != "" {
		awssso := doAuth(ctx)
		return openConsole(ctx, awssso, ctx.Cli.Console.AccountId, ctx.Cli.Console.Role)
	} else if haveAWSEnvVars(ctx) {
		creds := storage.RoleCredentials{
			AccessKeyId:     ctx.Cli.Console.AccessKeyId,
			SecretAccessKey: ctx.Cli.Console.SecretAccessKey,
			SessionToken:    ctx.Cli.Console.SessionToken,
		}

		// ask AWS STS for who we are
		s := session.Must(session.NewSession())
		stsSession := sts.New(s, aws.NewConfig().WithRegion("us-east-1"))
		input := sts.GetCallerIdentityInput{}
		output, err := stsSession.GetCallerIdentity(&input)
		if err != nil {
			return fmt.Errorf("Unable to call sts get-caller-identity: %s", err.Error())
		}

		accountid, role, err := utils.ParseRoleARN(aws.StringValue(output.Arn))
		if err != nil {
			return fmt.Errorf("Unable to parse ARN: %s", aws.StringValue(output.Arn))
		}

		region := ctx.Settings.GetDefaultRegion(accountid, role, false)
		if ctx.Cli.Console.Region != "" {
			region = ctx.Cli.Console.Region
		}
		return openConsoleAccessKey(ctx, &creds, duration, region)
	}

	// default action
	return consolePrompt(ctx)
}

func consolePrompt(ctx *RunContext) error {
	// use completer to figure out the role
	fmt.Printf("Please use `exit` or `Ctrl-D` to quit.\n")

	sso, err := ctx.Settings.GetSelectedSSO(ctx.Cli.SSO)
	if err != nil {
		return err
	}
	sso.Refresh(ctx.Settings)

	c := NewTagsCompleter(ctx, sso, openConsole)
	opts := ctx.Settings.DefaultOptions(c.ExitChecker)
	opts = append(opts, ctx.Settings.GetColorOptions()...)

	p := prompt.New(
		c.Executor,
		c.Complete,
		opts...,
	)

	p.Run()
	return nil
}

// haveAWSEnvVars returns true if we have all the AWS environment variables we need for a role
func haveAWSEnvVars(ctx *RunContext) bool {
	if ctx.Cli.Console.AccessKeyId == "" {
		return false
	}

	if ctx.Cli.Console.SecretAccessKey == "" {
		return false
	}

	if ctx.Cli.Console.SessionToken == "" {
		return false
	}

	return true
}

// opens the AWS console or just prints the URL
func openConsole(ctx *RunContext, awssso *sso.AWSSSO, accountid int64, role string) error {
	region := ctx.Settings.GetDefaultRegion(accountid, role, false)
	if ctx.Cli.Console.Region != "" {
		region = ctx.Cli.Console.Region
	}

	duration := ctx.Settings.ConsoleDuration
	if ctx.Cli.Console.Duration > 0 {
		duration = ctx.Cli.Console.Duration
	}

	ctx.Settings.Cache.AddHistory(utils.MakeRoleARN(accountid, role))
	if err := ctx.Settings.Cache.Save(false); err != nil {
		log.WithError(err).Warnf("Unable to update cache")
	}

	creds := GetRoleCredentials(ctx, awssso, accountid, role)

	return openConsoleAccessKey(ctx, creds, duration, region)
}

func openConsoleAccessKey(ctx *RunContext, creds *storage.RoleCredentials, duration int64, region string) error {
	signin := SigninTokenUrlParams{
		SessionDuration: duration * 60,
		Session: SessionUrlParams{
			AccessKeyId:     creds.AccessKeyId,
			SecretAccessKey: creds.SecretAccessKey,
			SessionToken:    creds.SessionToken,
		},
	}

	resp, err := http.Get(signin.GetUrl())
	if err != nil {
		return fmt.Errorf("Unable to login to AWS: %s", err.Error())
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	loginResponse := LoginResponse{}
	err = json.Unmarshal(body, &loginResponse)
	if err != nil {
		return fmt.Errorf("Error parsing Login response: %s", err.Error())
	}

	login := LoginUrlParams{
		Issuer:      "https://github.com/synfinatic/aws-sso-cli",
		Destination: fmt.Sprintf("https://console.aws.amazon.com/console/home?region=%s", region),
		SigninToken: loginResponse.SigninToken,
	}
	url := login.GetUrl()

	return utils.HandleUrl(ctx.Settings.UrlAction, ctx.Settings.Browser, url,
		"Please open the following URL in your browser:\n\n", "\n\n")
}

type LoginResponse struct {
	SigninToken string `json:"SigninToken"`
}

type SigninTokenUrlParams struct {
	SessionDuration int64
	Session         SessionUrlParams // URL encoded SessionUrlParams
}

func (stup *SigninTokenUrlParams) GetUrl() string {
	return fmt.Sprintf("%s?Action=getSigninToken&SessionDuration=%d&Session=%s",
		AWS_FEDERATED_URL, stup.SessionDuration, stup.Session.Encode())
}

type SessionUrlParams struct {
	AccessKeyId     string `json:"sessionId"`
	SecretAccessKey string `json:"sessionKey"`
	SessionToken    string `json:"sessionToken"`
}

func (sup *SessionUrlParams) Encode() string {
	s, _ := json.Marshal(sup)
	return url.QueryEscape(string(s))
}

type LoginUrlParams struct {
	Issuer      string
	Destination string
	SigninToken string
}

func (lup *LoginUrlParams) GetUrl() string {
	return fmt.Sprintf("%s?Action=login&Issuer=%s&Destination=%s&SigninToken=%s",
		AWS_FEDERATED_URL, lup.Issuer, lup.Destination,
		lup.SigninToken)
}

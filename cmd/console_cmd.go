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
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/c-bata/go-prompt"
	log "github.com/sirupsen/logrus"
	"github.com/synfinatic/aws-sso-cli/sso"
	"github.com/synfinatic/aws-sso-cli/storage"
	"github.com/synfinatic/aws-sso-cli/utils"
)

const AWS_FEDERATED_URL = "https://signin.aws.amazon.com/federation"

type ConsoleCmd struct {
	Region          string `kong:"optional,name='region',help='AWS Region',env='AWS_DEFAULT_REGION',predictor='region'"`
	AccessKeyId     string `kong:"optional,env='AWS_ACCESS_KEY_ID',hidden"`
	AccountId       int64  `kong:"optional,name='account',short='A',help='AWS AccountID of role to assume',env='AWS_SSO_ACCOUNTID',predictor='accountId'"`
	Arn             string `kong:"optional,short='a',help='ARN of role to assume',env='AWS_SSO_ROLE_ARN',predictor='arn'"`
	Duration        int64  `kong:"optional,short='d',help='AWS Session duration in minutes (default 60)',default=60,env='AWS_SSO_DURATION'"`
	Role            string `kong:"optional,short='R',help='Name of AWS Role to assume',env='AWS_SSO_ROLE',predictor='role'"`
	SecretAccessKey string `kong:"optional,env='AWS_SECRET_ACCESS_KEY',hidden"`
	SessionToken    string `kong:"optional,env='AWS_SESSION_TOKEN',hidden"`
	UseEnv          bool   `kong:"optional,short='e',help='Use existing ENV vars to generate URL'"`
}

func (cc *ConsoleCmd) Run(ctx *RunContext) error {
	if ctx.Cli.Console.Arn != "" {
		awssso := doAuth(ctx)

		accountid, role, err := utils.ParseRoleARN(ctx.Cli.Console.Arn)
		if err != nil {
			return err
		}

		region := ctx.Settings.GetDefaultRegion(accountid, role)
		if ctx.Cli.Console.Region != "" {
			region = ctx.Cli.Console.Region
		}
		return openConsole(ctx, awssso, accountid, role, region)
	} else if ctx.Cli.Console.AccountId != 0 || ctx.Cli.Console.Role != "" {
		if ctx.Cli.Console.AccountId == 0 || ctx.Cli.Console.Role == "" {
			return fmt.Errorf("Please specify both --account and --role")
		}
		awssso := doAuth(ctx)
		region := ctx.Settings.GetDefaultRegion(ctx.Cli.Console.AccountId, ctx.Cli.Console.Role)
		if ctx.Cli.Console.Region != "" {
			region = ctx.Cli.Console.Region
		}
		return openConsole(ctx, awssso, ctx.Cli.Console.AccountId, ctx.Cli.Console.Role, region)
	} else if ctx.Cli.Console.UseEnv {
		if ctx.Cli.Console.AccessKeyId == "" {
			return fmt.Errorf("AWS_ACCESS_KEY_ID is not set")
		}
		if ctx.Cli.Console.SecretAccessKey == "" {
			return fmt.Errorf("AWS_SECRET_ACCESS_KEY is not set")
		}
		if ctx.Cli.Console.SessionToken == "" {
			return fmt.Errorf("AWS_SESSION_TOKEN is not set")
		}
		creds := storage.RoleCredentials{
			AccessKeyId:     ctx.Cli.Console.AccessKeyId,
			SecretAccessKey: ctx.Cli.Console.SecretAccessKey,
			SessionToken:    ctx.Cli.Console.SessionToken,
		}
		accountid, err := strconv.ParseInt(os.Getenv("AWS_ACCOUNT_ID"), 10, 64)
		if err != nil {
			return fmt.Errorf("Unable to parse AWS_ACCOUNT_ID: %s", os.Getenv("AWS_ACCOUNT_ID"))
		}
		region := ctx.Settings.GetDefaultRegion(accountid, os.Getenv("AWS_ROLE_NAME"))
		if ctx.Cli.Console.Region != "" {
			region = ctx.Cli.Console.Region
		}
		return openConsoleAccessKey(ctx, &creds, ctx.Cli.Console.Duration, region)
	}

	fmt.Printf("Please use `exit` or `Ctrl-D` to quit.\n")

	// use completer to figure out the role
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

// opens the AWS console or just prints the URL
func openConsole(ctx *RunContext, awssso *sso.AWSSSO, accountid int64, role, region string) error {
	ctx.Settings.Cache.AddHistory(utils.MakeRoleARN(accountid, role), ctx.Settings.HistoryLimit)
	if err := ctx.Settings.Cache.Save(false); err != nil {
		log.WithError(err).Warnf("Unable to update cache")
	}

	creds := GetRoleCredentials(ctx, awssso, accountid, role)

	return openConsoleAccessKey(ctx, creds, ctx.Cli.Console.Duration, region)
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
		Issuer:      "https://github.com/synfinatic/aws-sso-cli", // FIXME
		Destination: fmt.Sprintf("https://console.aws.amazon.com/console/home?region=%s", region),
		SigninToken: loginResponse.SigninToken,
	}
	url := login.GetUrl()

	return utils.HandleUrl(ctx.Cli.UrlAction, ctx.Cli.Browser, url,
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

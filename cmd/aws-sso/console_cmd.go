package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2023 Aaron Turner  <synfinatic at gmail dot com>
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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os/user"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	// "github.com/davecgh/go-spew/spew"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	"github.com/synfinatic/aws-sso-cli/internal/url"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

const AWS_FEDERATED_URL = "https://signin.aws.amazon.com/federation"

type ConsoleCmd struct {
	// Console actually should honor the --region flag
	Duration int32  `kong:"short='d',help='AWS Session duration in minutes (default 60)'"` // default stored in DEFAULT_CONFIG
	Prompt   bool   `kong:"short='P',help='Force interactive prompt to select role'"`
	NoCache  bool   `kong:"help='Do not use cache'"`
	Region   string `kong:"help='AWS Region',env='AWS_DEFAULT_REGION',predictor='region'"`

	Arn       string `kong:"short='a',help='ARN of role to assume',env='AWS_SSO_ROLE_ARN',predictor='arn'"`
	AccountId int64  `kong:"name='account',short='A',help='AWS AccountID of role to assume',env='AWS_SSO_ACCOUNT_ID',predictor='accountId'"`
	Role      string `kong:"short='R',help='Name of AWS Role to assume',env='AWS_SSO_ROLE_NAME',predictor='role'"`
	Profile   string `kong:"short='p',help='Name of AWS Profile to assume',predictor='profile'"`

	AccessKeyId     string `kong:"env='AWS_ACCESS_KEY_ID',hidden"`
	SecretAccessKey string `kong:"env='AWS_SECRET_ACCESS_KEY',hidden"`
	SessionToken    string `kong:"env='AWS_SESSION_TOKEN',hidden"`
	AwsProfile      string `kong:"env='AWS_PROFILE',hidden"`
}

func (cc *ConsoleCmd) Run(ctx *RunContext) error {
	if ctx.Cli.Console.Duration > 0 {
		ctx.Settings.ConsoleDuration = ctx.Cli.Console.Duration
	}

	if ctx.Settings.ConsoleDuration > 0 && (ctx.Settings.ConsoleDuration < 15 || ctx.Settings.ConsoleDuration > 720) {
		return fmt.Errorf("Invalid --duration %d.  Must be between 15 and 720", ctx.Settings.ConsoleDuration)
	}

	if ctx.Cli.Console.NoCache {
		c := &CacheCmd{}
		if err := c.Run(ctx); err != nil {
			return err
		}
	}

	// do we force interactive prompt?
	if ctx.Cli.Console.Prompt {
		return ctx.PromptExec(openConsole)
	}

	// Check our CLI args
	sci := NewSelectCliArgs(ctx.Cli.Console.Arn, ctx.Cli.Console.AccountId, ctx.Cli.Console.Role, ctx.Cli.Console.Profile)
	if err := sci.Update(ctx); err == nil {
		// successful lookup?
		return openConsole(ctx, sci.AccountId, sci.RoleName)
	}

	// Check our various ENV vars
	if haveAWSEnvVars(ctx) {
		return consoleViaEnvVars(ctx)
	} else if ctx.Cli.Console.AwsProfile != "" {
		ssoCache := ctx.Settings.Cache.GetSSO()
		_, err := ssoCache.Roles.GetRoleByProfile(ctx.Cli.Console.AwsProfile, ctx.Settings)
		if err == nil {
			return consoleViaSDK(ctx)
		}
		log.Warnf("AWS_PROFILE=%s was not found in our cache.", ctx.Cli.Console.AwsProfile)
	}

	// fall back to interactive prompting...
	return ctx.PromptExec(openConsole)
}

func stsSession(ctx *RunContext) (*sts.Client, error) {
	cfgCreds := credentials.NewStaticCredentialsProvider(
		ctx.Cli.Console.AccessKeyId,
		ctx.Cli.Console.SecretAccessKey,
		ctx.Cli.Console.SessionToken,
	)

	sso, err := ctx.Settings.GetSelectedSSO(ctx.Cli.SSO)
	if err != nil {
		return &sts.Client{}, err
	}

	ssoRegion := sso.SSORegion
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(ssoRegion),
		config.WithCredentialsProvider(cfgCreds),
	)
	if err != nil {
		return &sts.Client{}, err
	}

	return sts.NewFromConfig(cfg), nil
}

func consoleViaEnvVars(ctx *RunContext) error {
	// ask AWS STS for who we are so we can look it up in our cache

	stsHandle, err := stsSession(ctx)
	if err != nil {
		return err
	}

	input := sts.GetCallerIdentityInput{}
	output, err := stsHandle.GetCallerIdentity(context.TODO(), &input)
	if err != nil {
		return fmt.Errorf("Unable to call sts get-caller-identity: %s", err.Error())
	}

	accountid, role, err := utils.ParseRoleARN(aws.ToString(output.Arn))
	if err != nil {
		return fmt.Errorf("Unable to parse ARN: %s", aws.ToString(output.Arn))
	}

	// now we know who we are, get our configured default region
	region := ctx.Settings.GetDefaultRegion(accountid, role, false)
	if ctx.Cli.Console.Region != "" {
		region = ctx.Cli.Console.Region
	}

	creds := storage.RoleCredentials{
		AccessKeyId:     ctx.Cli.Console.AccessKeyId,
		SecretAccessKey: ctx.Cli.Console.SecretAccessKey,
		SessionToken:    ctx.Cli.Console.SessionToken,
	}
	return openConsoleAccessKey(ctx, &creds, ctx.Settings.ConsoleDuration, region, accountid, role)
}

func consoleViaSDK(ctx *RunContext) error {
	rFlat, err := ctx.Settings.Cache.GetSSO().Roles.GetRoleByProfile(ctx.Cli.Console.AwsProfile, ctx.Settings)
	if err == nil {
		return openConsole(ctx, rFlat.AccountId, rFlat.RoleName)
	}

	region := ctx.Settings.DefaultRegion
	if ctx.Cli.Console.Region != "" {
		region = ctx.Cli.Console.Region
	}
	if region == "" {
		region = "us-east-1" // need a region for a valid url!
	}

	// have to use the Go SDK to load our creds because apparently the profile
	// is based on static API creds

	stsHandle, err := stsSession(ctx)
	if err != nil {
		return err
	}

	u, err := user.Current()
	if err != nil {
		return err
	}

	input := sts.GetFederationTokenInput{
		DurationSeconds: aws.Int32(ctx.Settings.ConsoleDuration * 60),
		Name:            aws.String(u.Username),
	}
	token, err := stsHandle.GetFederationToken(context.TODO(), &input)
	if err != nil {
		return err
	}
	creds := storage.RoleCredentials{
		AccessKeyId:     aws.ToString(token.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(token.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(token.Credentials.SessionToken),
	}

	return openConsoleAccessKey(ctx, &creds, ctx.Settings.ConsoleDuration, region,
		rFlat.AccountId, rFlat.RoleName)
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
func openConsole(ctx *RunContext, accountid int64, role string) error {
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

	creds := GetRoleCredentials(ctx, AwsSSO, accountid, role)
	return openConsoleAccessKey(ctx, creds, duration, region, accountid, role)
}

// openConsoleAccessKey opens the Frederated Console access URL
func openConsoleAccessKey(ctx *RunContext, creds *storage.RoleCredentials,
	duration int32, region string, accountId int64, role string) error {
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
		log.Debugf(err.Error())
		// sanitize error and remove sensitive URL from normal output
		r := regexp.MustCompile(`Get "[^"]+": `)
		e := r.ReplaceAllString(err.Error(), "")
		return fmt.Errorf("Unable to login to AWS: %s", e)
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

	sso, err := ctx.Settings.GetSelectedSSO(ctx.Cli.SSO)
	if err != nil {
		return err
	}
	issuer := sso.StartUrl

	login := LoginUrlParams{
		Issuer:      issuer,
		Destination: fmt.Sprintf("https://console.aws.amazon.com/console/home?region=%s", region),
		SigninToken: loginResponse.SigninToken,
	}

	urlOpener := url.NewHandleUrl(ctx.Settings.UrlAction, login.GetUrl(),
		ctx.Settings.Browser, ctx.Settings.UrlExecCommand)

	urlOpener.ContainerSettings(containerParams(ctx, accountId, role))

	return urlOpener.Open()
}

// containerParams generates the name, color, icon for the Firefox container plugin
func containerParams(ctx *RunContext, accountId int64, role string) (string, string, string) {
	rFlat, _ := ctx.Settings.Cache.GetRole(utils.MakeRoleARN(accountId, role))
	profile, err := rFlat.ProfileName(ctx.Settings)
	if err != nil && strings.Contains(profile, "&") {
		profile = fmt.Sprintf("%d:%s", accountId, role)
	}

	color := rFlat.Tags["Color"]
	icon := rFlat.Tags["Icon"]

	return profile, color, icon
}

type LoginResponse struct {
	SigninToken string `json:"SigninToken"`
}

type SigninTokenUrlParams struct {
	SessionDuration int32
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
	return neturl.QueryEscape(string(s))
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

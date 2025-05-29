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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/synfinatic/aws-sso-cli/internal/sso"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

type ExecCmd struct {
	// AWS Params
	Arn        string `kong:"short='a',help='ARN of role to assume',env='AWS_SSO_ROLE_ARN',predictor='arn'"`
	AccountId  int64  `kong:"name='account',short='A',help='AWS AccountID of role to assume',env='AWS_SSO_ACCOUNT_ID',predictor='accountId'"`
	Role       string `kong:"short='R',help='Name of AWS Role to assume',env='AWS_SSO_ROLE_NAME',predictor='role'"`
	Profile    string `kong:"short='p',help='Name of AWS Profile to assume',predictor='profile'"`
	NoRegion   bool   `kong:"short='n',help='Do not set AWS_DEFAULT_REGION from config.yaml'"`
	STSRefresh bool   `kong:"help='Force refresh of STS Token Credentials'"`
	IgnoreEnv  bool   `kong:"short='i',help='Force execution even if AWS_* environment variables are set'"`

	// Exec Params
	Cmd  string   `kong:"arg,optional,name='command',help='Command to execute',env='SHELL'"`
	Args []string `kong:"arg,optional,passthrough,name='args',help='Associated arguments for the command'"`
}

// AfterApply determines if SSO auth token is required
func (e ExecCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_REQUIRED
	return nil
}

func (cc *ExecCmd) Run(ctx *RunContext) error {
	if !ctx.Cli.Exec.IgnoreEnv {
		err := checkAwsEnvironment()
		if err != nil {
			log.Fatal("Unable to continue", "error", err.Error())
		}
	}

	if ctx.Cli.Exec.Cmd == "" {
		if runtime.GOOS == "windows" {
			// Windows doesn't set $SHELL, so default to CommandPrompt
			ctx.Cli.Exec.Cmd = "cmd.exe"
		} else if os.Getenv("XONSH_VERSION") != "" {
			// Xonsh doesn't set $SHELL, so default to xonsh
			ctx.Cli.Exec.Cmd = "xonsh"
		}
	}

	sci := NewSelectCliArgs(ctx.Cli.Exec.Arn, ctx.Cli.Exec.AccountId, ctx.Cli.Exec.Role, ctx.Cli.Exec.Profile)
	if err := sci.Update(ctx); err == nil {
		// successful lookup?
		return execCmd(ctx, sci.AccountId, sci.RoleName)
	} else if !errors.Is(err, &NoRoleSelectedError{}) {
		// invalid arguments, not missing
		return err
	}

	return ctx.PromptExec(execCmd)
}

// Executes Cmd+Args in the context of the AWS Role creds
func execCmd(ctx *RunContext, accountid int64, role string) error {
	region := ctx.Settings.GetDefaultRegion(accountid, role, ctx.Cli.Exec.NoRegion)

	ctx.Settings.Cache.AddHistory(utils.MakeRoleARN(accountid, role))
	if err := ctx.Settings.Cache.Save(false); err != nil {
		log.Warn("Unable to update cache", "error", err.Error())
	}

	// ready our command and connect everything up
	cmd := exec.Command(ctx.Cli.Exec.Cmd, ctx.Cli.Exec.Args...) // #nosec
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	cmd.Env = os.Environ() // copy our current environment to the executor

	// add the variables we need for AWS to the executor without polluting our
	// own process
	for k, v := range execShellEnvs(ctx, accountid, role, region) {
		log.Debug("Setting", "variable", k, "value", v)
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}
	// just do it!
	return cmd.Run()
}

func execShellEnvs(ctx *RunContext, accountid int64, role, region string) map[string]string {
	var err error
	credsPtr := GetRoleCredentials(ctx, AwsSSO, ctx.Cli.Exec.STSRefresh, accountid, role)
	creds := *credsPtr

	ssoName, _ := ctx.Settings.GetSelectedSSOName(ctx.Cli.SSO)
	shellVars := map[string]string{
		"AWS_ACCESS_KEY_ID":          creds.AccessKeyId,
		"AWS_SECRET_ACCESS_KEY":      creds.SecretAccessKey,
		"AWS_SESSION_TOKEN":          creds.SessionToken,
		"AWS_SSO_ACCOUNT_ID":         creds.AccountIdStr(),
		"AWS_SSO_ROLE_NAME":          creds.RoleName,
		"AWS_SSO_SESSION_EXPIRATION": creds.ExpireString(),
		"AWS_SSO_ROLE_ARN":           utils.MakeRoleARN(creds.AccountId, creds.RoleName),
		"AWS_SSO":                    ssoName,
	}

	if len(region) > 0 {
		shellVars["AWS_DEFAULT_REGION"] = region
		shellVars["AWS_SSO_DEFAULT_REGION"] = region
	} else {
		// we no longer manage the region
		shellVars["AWS_SSO_DEFAULT_REGION"] = ""
	}

	// Set the AWS_SSO_PROFILE env var using our template
	cache := ctx.Settings.Cache.GetSSO()
	var roleInfo *sso.AWSRoleFlat
	if roleInfo, err = cache.Roles.GetRole(accountid, role); err != nil {
		// this error should never happen
		log.Error("Unable to find role in cache.  Unable to set AWS_SSO_PROFILE")
	} else {
		shellVars["AWS_SSO_PROFILE"], err = roleInfo.ProfileName(ctx.Settings)
		if err != nil {
			log.Error("Unable to generate AWS_SSO_PROFILE", "error", err.Error())
		}

		// and any EnvVarTags
		for k, v := range roleInfo.GetEnvVarTags(ctx.Settings) {
			shellVars[k] = v
		}
	}

	return shellVars
}

// returns an error if we have existing AWS env vars
func checkAwsEnvironment() error {
	checkVars := []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE"}
	for _, envVar := range checkVars {
		if _, ok := os.LookupEnv(envVar); ok {
			return fmt.Errorf("conflicting environment variable '%s' is set", envVar)
		}
	}
	return nil
}

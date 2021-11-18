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
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/template"

	"github.com/c-bata/go-prompt"
	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
	"github.com/synfinatic/aws-sso-cli/sso"
	"github.com/synfinatic/aws-sso-cli/utils"
)

type ExecCmd struct {
	// AWS Params
	Duration  int64  `kong:"short='d',help='AWS Session duration in minutes (default 60)',default=60,env='AWS_SSO_DURATION'"`
	Arn       string `kong:"short='a',help='ARN of role to assume',env='AWS_SSO_ROLE_ARN',predictor='arn',xor='arn-1',xor='arn-2'"`
	AccountId int64  `kong:"name='account',short='A',help='AWS AccountID of role to assume',env='AWS_SSO_ACCOUNTID',predictor='accountId',xor='arn-1'"`
	Role      string `kong:"short='R',help='Name of AWS Role to assume',env='AWS_SSO_ROLE',predictor='role',xor='arn-2'"`

	// Exec Params
	Cmd  string   `kong:"arg,optional,name='command',help='Command to execute',env='SHELL'"`
	Args []string `kong:"arg,optional,passthrough,name='args',help='Associated arguments for the command'"`
}

func (cc *ExecCmd) Run(ctx *RunContext) error {
	err := checkAwsEnvironment()
	if err != nil {
		log.WithError(err).Fatalf("Unable to continue")
	}

	// Did user specify the ARN or account/role?
	if ctx.Cli.Exec.Arn != "" {
		awssso := doAuth(ctx)

		accountid, role, err := utils.ParseRoleARN(ctx.Cli.Exec.Arn)
		if err != nil {
			return err
		}

		return execCmd(ctx, awssso, accountid, role)
	} else if ctx.Cli.Exec.AccountId != 0 || ctx.Cli.Exec.Role != "" {
		if ctx.Cli.Exec.AccountId == 0 || ctx.Cli.Exec.Role == "" {
			return fmt.Errorf("Please specify both --account and --role")
		}
		awssso := doAuth(ctx)

		return execCmd(ctx, awssso, ctx.Cli.Exec.AccountId, ctx.Cli.Exec.Role)
	}

	// Nope, auto-complete mode...
	sso, err := ctx.Settings.GetSelectedSSO(ctx.Cli.SSO)
	if err != nil {
		return err
	}
	if err = ctx.Settings.Cache.Expired(sso); err != nil {
		log.Warnf(err.Error())
		c := &CacheCmd{}
		if err = c.Run(ctx); err != nil {
			return err
		}
	}

	sso.Refresh(ctx.Settings)
	fmt.Printf("Please use `exit` or `Ctrl-D` to quit.\n")

	c := NewTagsCompleter(ctx, sso, execCmd)
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

const (
	AwsSsoProfileTemplate = "{{.AccountId}}:{{.RoleName}}"
)

func emptyString(str string) bool {
	return str == ""
}

func firstItem(items []string) string {
	for _, v := range items {
		if v != "" {
			return v
		}
	}
	return ""
}

func accountIdToStr(id int64) string {
	return strconv.FormatInt(id, 10)
}

// Executes Cmd+Args in the context of the AWS Role creds
func execCmd(ctx *RunContext, awssso *sso.AWSSSO, accountid int64, role string) error {
	ctx.Settings.Cache.AddHistory(utils.MakeRoleARN(accountid, role), ctx.Settings.HistoryLimit)
	if err := ctx.Settings.Cache.Save(false); err != nil {
		log.WithError(err).Warnf("Unable to update cache")
	}

	// ready our command and connect everything up
	cmd := exec.Command(ctx.Cli.Exec.Cmd, ctx.Cli.Exec.Args...) // #nosec
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin

	for k, v := range execShellEnvs(ctx, awssso, accountid, role) {
		log.Debugf("Setting %s = %s", k, v)
		os.Setenv(k, v)
	}
	// just do it!
	return cmd.Run()
}

func execShellEnvs(ctx *RunContext, awssso *sso.AWSSSO, accountid int64, role string) map[string]string {
	credsPtr := GetRoleCredentials(ctx, awssso, accountid, role)
	creds := *credsPtr

	shellVars := map[string]string{
		"AWS_ACCESS_KEY_ID":      creds.AccessKeyId,
		"AWS_SECRET_ACCESS_KEY":  creds.SecretAccessKey,
		"AWS_SESSION_TOKEN":      creds.SessionToken,
		"AWS_ACCOUNT_ID":         creds.AccountIdStr(),
		"AWS_ROLE_NAME":          creds.RoleName,
		"AWS_SESSION_EXPIRATION": creds.ExpireString(),
	}

	var profileFormat string = AwsSsoProfileTemplate

	funcMap := template.FuncMap{
		"AccountIdStr": accountIdToStr,
		"EmptyString":  emptyString,
		"FirstItem":    firstItem,
		"StringsJoin":  strings.Join,
	}

	if ctx.Settings.ProfileFormat != "" {
		profileFormat = ctx.Settings.ProfileFormat
	}

	// Set the AWS_SSO_PROFILE env var using our template
	var templ *template.Template
	if roleInfo, err := ctx.Settings.Cache.Roles.GetRole(accountid, role); err != nil {
		// this error should never happen
		log.Errorf("Unable to find role in cache.  Unable to set AWS_SSO_PROFILE")
	} else {
		templ, err = template.New("main").Funcs(funcMap).Parse(profileFormat)
		if err != nil {
			log.Errorf("Invalid ProfileFormat '%s': %s -- using default", ctx.Settings.ProfileFormat, err)
			templ, _ = template.New("main").Funcs(funcMap).Parse(AwsSsoProfileTemplate)
		}

		buf := new(bytes.Buffer)
		log.Tracef("RoleInfo: %s", spew.Sdump(roleInfo))
		log.Tracef("Template: %s", spew.Sdump(templ))
		if err := templ.Execute(buf, roleInfo); err != nil {
			log.WithError(err).Errorf("Unable to generate AWS_SSO_PROFILE")
		}
		shellVars["AWS_SSO_PROFILE"] = buf.String()
	}

	return shellVars
}

// returns an error if we have existing AWS env vars
func checkAwsEnvironment() error {
	checkVars := []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE"}
	for _, envVar := range checkVars {
		if _, ok := os.LookupEnv(envVar); ok {
			return fmt.Errorf("Conflicting environment variable '%s' is set", envVar)
		}
	}
	return nil
}

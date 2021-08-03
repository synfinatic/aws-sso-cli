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
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v3"

	"github.com/Songmu/prompter"
	"github.com/c-bata/go-prompt"
)

type ExecCmd struct {
	// AWS Params
	Region    string `kong:"optional,name='region',help='AWS Region',env='AWS_DEFAULT_REGION'"`
	Duration  int64  `kong:"optional,name='duration',short='d',help='AWS Session duration in minutes (default 60)',default=60,env='AWS_SSO_DURATION'"`
	Arn       string `kong:"optional,name='arn',short='a',help='ARN of role to assume',env='AWS_SSO_ROLE_ARN'"`
	AccountId string `kong:"optional,name='account',short='A',help='AWS AccountID of role to assume',env='AWS_SSO_ACCOUNTID'"`
	Role      string `kong:"optional,name='role',short='R',help='Name of AWS Role to assume',env='AWS_SSO_ROLE'"`

	// Exec Params
	Cmd  string   `kong:"arg,optional,name='command',help='Command to execute',env='SHELL'"`
	Args []string `kong:"arg,optional,name='args',help='Associated arguments for the command'"`
}

func (cc *ExecCmd) Run(ctx *RunContext) error {
	err := checkAwsEnvironment()
	if err != nil {
		log.WithError(err).Fatalf("Unable to continue")
	}

	// Did user specify the ARN or account/role?
	if ctx.Cli.Exec.Arn != "" {
		awssso := doAuth(ctx)
		s := strings.Split(ctx.Cli.Exec.Arn, ":")
		var accountid, role string
		if len(s) == 2 {
			// short account:Role format
			accountid = s[0]
			role = s[1]
		} else {
			// long format for arn:aws:iam:XXXXXXXXXX:role/YYYYYYYY
			accountid = s[3]
			s = strings.Split(s[4], "/")
			role = s[1]
		}
		return execCmd(ctx, awssso, accountid, role)
	} else if ctx.Cli.Exec.AccountId != "" || ctx.Cli.Exec.Role != "" {
		if ctx.Cli.Exec.AccountId == "" || ctx.Cli.Exec.Role == "" {
			return fmt.Errorf("Please specify both --account and --role")
		}
		awssso := doAuth(ctx)
		return execCmd(ctx, awssso, ctx.Cli.Exec.AccountId, ctx.Cli.Exec.Role)
	}

	fmt.Printf("Please use `exit` or `Ctrl-D` to quit.\n")

	// use completer to figure out the role
	sso := ctx.Config.SSO[ctx.Cli.SSO]
	sso.Refresh()
	c := NewTagsCompleter(ctx, sso)
	p := prompt.New(
		c.Executor,
		c.Complete,
		prompt.OptionPrefix("> "),
		prompt.OptionSetExitCheckerOnInput(c.ExitChecker),
		prompt.OptionCompletionOnDown(),
		prompt.OptionShowCompletionAtStart(),
	)
	p.Run()
	return nil
}

// Creates an AWSSO object post authentication
func doAuth(ctx *RunContext) *AWSSSO {
	sso := ctx.Config.SSO[ctx.Cli.SSO]
	awssso := NewAWSSSO(sso.SSORegion, sso.StartUrl, &ctx.Store)
	err := awssso.Authenticate(ctx.Config.PrintUrl, ctx.Config.Browser)
	if err != nil {
		log.WithError(err).Fatalf("Unable to authenticate")
	}
	return awssso
}

// Executes Cmd+Args in the context of the AWS Role creds
func execCmd(ctx *RunContext, awssso *AWSSSO, accountid, role string) error {
	creds, err := awssso.GetRoleCredentials(accountid, role)
	if err != nil {
		log.WithError(err).Fatalf("Unable to get role credentials for %s", role)
	}

	// set our ENV & execute the command
	os.Setenv("AWS_ACCESS_KEY_ID", creds.AccessKeyId)
	os.Setenv("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)
	os.Setenv("AWS_SESSION_TOKEN", creds.SessionToken)
	os.Setenv("AWS_ACCOUNT_ID", creds.AccountId)
	os.Setenv("AWS_ROLE_NAME", creds.RoleName)
	if ctx.Cli.Exec.Region != "" {
		os.Setenv("AWS_DEFAULT_REGION", ctx.Cli.Exec.Region)
	}
	os.Setenv("AWS_SESSION_EXPIRATION", creds.ExpireString())
	//	os.Setenv("AWS_SSO_PROFILE", cli.Exec.Profile)
	os.Setenv("AWS_ROLE_ARN", creds.RoleArn())

	// ready our command and connect everything up
	cmd := exec.Command(ctx.Cli.Exec.Cmd, ctx.Cli.Exec.Args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin

	// just do it!
	return cmd.Run()
}

func updateRoleCache(ctx *RunContext, sso *SSOConfig, awssso *AWSSSO, roles *map[string][]RoleInfo) error {
	roles = &map[string][]RoleInfo{} // zero out roles if we are doing a --force-update

	accounts, err := awssso.GetAccounts()
	if err != nil {
		return fmt.Errorf("Unable to get accounts: %s", err.Error())
	}

	for _, a := range accounts {
		account := a.AccountId
		roleInfo, err := awssso.GetRoles(a)
		if err != nil {
			return fmt.Errorf("Unable to get roles for AccountId %s: %s",
				account, err.Error())
		}

		rroles := *roles
		for _, r := range roleInfo {
			rroles[account] = append(rroles[account], r)
		}
	}
	ctx.Cache.SaveRoles(*roles)

	// now update our config.yaml
	changes, err := sso.UpdateRoles(*roles)
	if err != nil {
		return fmt.Errorf("Unable to update our config file: %s", err.Error())
	}
	if changes > 0 {
		p := fmt.Sprintf("Update config file with %d new roles?", changes)
		if prompter.YN(p, true) {
			b, _ := yaml.Marshal(ctx.Config)
			cfile := fmt.Sprintf("%s", ctx.Cli.ConfigFile)
			err = ioutil.WriteFile(cfile, b, 0644)
			if err != nil {
				return fmt.Errorf("Unable to save config: %s", err.Error())
			}
		}
	}
	return nil
}

// returns an error if we have existing AWS env vars
func checkAwsEnvironment() error {
	checkVars := []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE"}
	for _, envVar := range checkVars {
		if _, exist := os.LookupEnv(envVar); exist == true {
			return fmt.Errorf("Conflicting environment variable '%s' is set", envVar)
		}
	}
	return nil
}

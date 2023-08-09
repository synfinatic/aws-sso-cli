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
	"fmt"

	"github.com/c-bata/go-prompt"
	"github.com/synfinatic/aws-sso-cli/sso"
)

type EcsCmd struct {
	Run  EcsRunCmd  `kong:"cmd,help='Run the ECS Server'"`
	Load EcsLoadCmd `kong:"cmd,help='Load new IAM Role credentials into the ECS Server'"`
}

type EcsRunCmd struct {
	Port uint16 `kong:"help='TCP port to listen on',env='AWS_SSO_ECS_PORT',required"`
}

type EcsLoadCmd struct {
	// AWS Params
	Arn       string `kong:"short='a',help='ARN of role to assume',env='AWS_SSO_ROLE_ARN',predictor='arn'"`
	AccountId int64  `kong:"name='account',short='A',help='AWS AccountID of role to assume',env='AWS_SSO_ACCOUNT_ID',predictor='accountId'"`
	Role      string `kong:"short='R',help='Name of AWS Role to assume',env='AWS_SSO_ROLE_NAME',predictor='role'"`
	Profile   string `kong:"short='p',help='Name of AWS Profile to assume',predictor='profile'"`

	// Other params
	Port uint16 `kong:"help='TCP port of aws-sso ECS Server',env='AWS_SSO_ECS_PORT',required"`
}

func (cc *EcsRunCmd) Run(ctx *RunContext) error {
	return nil
}

func (cc *EcsLoadCmd) Run(ctx *RunContext) error {
	sci := NewSelectCliArgs(ctx.Cli.Exec.Arn, ctx.Cli.Exec.AccountId, ctx.Cli.Exec.Role, ctx.Cli.Exec.Profile)
	if awssso, err := sci.Update(ctx); err == nil {
		// successful lookup?
		return ecsLoadCmd(ctx, awssso, sci.AccountId, sci.RoleName)
	}

	// nope, auto-complete mode
	sso, err := ctx.Settings.GetSelectedSSO(ctx.Cli.SSO)
	if err != nil {
		return err
	}
	if err = ctx.Settings.Cache.Expired(sso); err != nil {
		log.Infof(err.Error())
		c := &CacheCmd{}
		if err = c.Run(ctx); err != nil {
			return err
		}
	}

	sso.Refresh(ctx.Settings)
	fmt.Printf("Please use `exit` or `Ctrl-D` to quit.\n")

	c := NewTagsCompleter(ctx, sso, ecsLoadCmd)
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

// Loads our AWS API creds into the ECS Server
func ecsLoadCmd(ctx *RunContext, awssso *sso.AWSSSO, accountId int64, role string) error {
	_ = GetRoleCredentials(ctx, awssso, accountId, role)
	//	creds := *credsPtr

	// do something
	return nil
}

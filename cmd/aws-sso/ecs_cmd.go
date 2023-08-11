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
	"context"
	"fmt"

	"github.com/synfinatic/aws-sso-cli/internal/server"
	//	"github.com/synfinatic/aws-sso-cli/internal/utils"
	"github.com/davecgh/go-spew/spew"
	"github.com/synfinatic/aws-sso-cli/sso"
)

const (
	ECS_PORT = 4144
)

type EcsCmd struct {
	Run     EcsRunCmd     `kong:"cmd,help='Run the ECS Server'"`
	Load    EcsLoadCmd    `kong:"cmd,help='Load new IAM Role credentials into the ECS Server'"`
	Unload  EcsUnloadCmd  `kong:"cmd,help='Unload the current IAM Role credentials from the ECS Server'"`
	Profile EcsProfileCmd `kong:"cmd,help='Get the current role profile name in the default slot'"`
}

type EcsRunCmd struct {
	Port int `kong:"help='TCP port to listen on',env='AWS_SSO_ECS_PORT',default=4144"`
}

type EcsLoadCmd struct {
	// AWS Params
	Arn       string `kong:"short='a',help='ARN of role to assume',env='AWS_SSO_ROLE_ARN',predictor='arn'"`
	AccountId int64  `kong:"name='account',short='A',help='AWS AccountID of role to assume',env='AWS_SSO_ACCOUNT_ID',predictor='accountId',xor='account'"`
	Role      string `kong:"short='R',help='Name of AWS Role to assume',env='AWS_SSO_ROLE_NAME',predictor='role',xor='role'"`
	Profile   string `kong:"short='p',help='Name of AWS Profile to assume',predictor='profile',xor='account,role'"`

	// Other params
	Port    int  `kong:"help='TCP port of aws-sso ECS Server',env='AWS_SSO_ECS_PORT',default=4144"`
	Slotted bool `kong:"short='s',help='Load credentials in a unique slot using the ProfileName as the key'"`
}

type EcsProfileCmd struct {
	Port int `kong:"help='TCP port of aws-sso ECS Server',env='AWS_SSO_ECS_PORT',default=4144"`
}

type EcsUnloadCmd struct {
	Port    int    `kong:"help='TCP port of aws-sso ECS Server',env='AWS_SSO_ECS_PORT',default=4144"`
	Profile string `kong:"short='p',help='Name of AWS Profile to unload',predictor='profile'"`
}

func (cc *EcsRunCmd) Run(ctx *RunContext) error {
	s, err := server.NewEcsServer(context.TODO(), "", ctx.Cli.Ecs.Run.Port)
	if err != nil {
		return err
	}
	return s.Serve()
}

func (cc *EcsLoadCmd) Run(ctx *RunContext) error {
	sci := NewSelectCliArgs(ctx.Cli.Ecs.Load.Arn, ctx.Cli.Ecs.Load.AccountId, ctx.Cli.Ecs.Load.Role, ctx.Cli.Ecs.Load.Profile)
	if awssso, err := sci.Update(ctx); err == nil {
		// successful lookup?
		return ecsLoadCmd(ctx, awssso, sci.AccountId, sci.RoleName)
	}

	return ctx.PromptExec(ecsLoadCmd)
}

func (cc *EcsProfileCmd) Run(ctx *RunContext) error {
	c := server.NewClient(ctx.Cli.Ecs.Profile.Port)

	profile, err := c.GetProfile()
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", profile)
	return nil
}

func (cc *EcsUnloadCmd) Run(ctx *RunContext) error {
	c := server.NewClient(ctx.Cli.Ecs.Unload.Port)

	return c.Delete(ctx.Cli.Ecs.Unload.Profile)
}

// Loads our AWS API creds into the ECS Server
func ecsLoadCmd(ctx *RunContext, awssso *sso.AWSSSO, accountId int64, role string) error {
	creds := GetRoleCredentials(ctx, awssso, accountId, role)

	cache := ctx.Settings.Cache.GetSSO() // ctx.Settings.Cache.Refresh(awssso, ssoConfig, ctx.Cli.SSO)
	rFlat, err := cache.Roles.GetRole(accountId, role)
	if err != nil {
		return err
	}

	// generate our ProfileName if necessary
	p, err := rFlat.ProfileName(ctx.Settings)
	if err == nil {
		rFlat.Profile = p
	}

	// do something
	c := server.NewClient(ctx.Cli.Ecs.Load.Port)

	log.Debugf("%s", spew.Sdump(rFlat))
	return c.SubmitCreds(creds, rFlat.Profile, ctx.Cli.Ecs.Load.Slotted)
}

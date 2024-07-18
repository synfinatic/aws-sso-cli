package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2024 Aaron Turner  <synfinatic at gmail dot com>
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
	"sort"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	"github.com/synfinatic/aws-sso-cli/internal/ecs/client"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
	"github.com/synfinatic/gotable"
)

type EcsLoadCmd struct {
	// AWS Params
	Arn        string `kong:"short='a',help='ARN of role to load',env='AWS_SSO_ROLE_ARN',predictor='arn'"`
	AccountId  int64  `kong:"name='account',short='A',help='AWS AccountID of role to load',env='AWS_SSO_ACCOUNT_ID',predictor='accountId',xor='account'"`
	Role       string `kong:"short='R',help='Name of AWS Role to load',env='AWS_SSO_ROLE_NAME',predictor='role',xor='role'"`
	Profile    string `kong:"short='p',help='Name of AWS Profile to load',predictor='profile',xor='account,role'"`
	STSRefresh bool   `kong:"help='Force refresh of STS Token Credentials'"`

	// Other params
	Server  string `kong:"help='Endpoint of aws-sso ECS Server',env='AWS_SSO_ECS_SERVER',default='localhost:4144'"`
	Slotted bool   `kong:"short='s',help='Load credentials in a unique slot using the ProfileName as the key'"`
}

// AfterApply determines if SSO auth token is required
func (l EcsLoadCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_REQUIRED
	return nil
}

func (cc *EcsLoadCmd) Run(ctx *RunContext) error {
	sci := NewSelectCliArgs(ctx.Cli.Ecs.Load.Arn, ctx.Cli.Ecs.Load.AccountId, ctx.Cli.Ecs.Load.Role, ctx.Cli.Ecs.Load.Profile)
	if err := sci.Update(ctx); err == nil {
		// successful lookup?
		return ecsLoadCmd(ctx, sci.AccountId, sci.RoleName)
	} else if !errors.Is(err, &NoRoleSelectedError{}) {
		// invalid arguments, not missing
		return err
	}

	return ctx.PromptExec(ecsLoadCmd)
}

type EcsProfileCmd struct {
	Server string `kong:"help='URL endpoint of aws-sso ECS Server',env='AWS_SSO_ECS_SERVER',default='localhost:4144'"`
}

// AfterApply determines if SSO auth token is required
func (l EcsProfileCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_NO_CONFIG
	return nil
}

func (cc *EcsProfileCmd) Run(ctx *RunContext) error {
	c := newClient(ctx.Cli.Ecs.Profile.Server, ctx)

	profile, err := c.GetProfile()
	if err != nil {
		return err
	}

	if profile.ProfileName == "" {
		return fmt.Errorf("no profile loaded in ECS Server")
	}

	profiles := []ecs.ListProfilesResponse{
		profile,
	}
	return listProfiles(profiles)
}

// Loads our AWS API creds into the ECS Server
func ecsLoadCmd(ctx *RunContext, accountId int64, role string) error {
	c := newClient(ctx.Cli.Ecs.Load.Server, ctx)

	creds := GetRoleCredentials(ctx, AwsSSO, ctx.Cli.Ecs.Load.STSRefresh, accountId, role)

	cache := ctx.Settings.Cache.GetSSO()
	rFlat, err := cache.Roles.GetRole(accountId, role)
	if err != nil {
		return err
	}

	// generate our ProfileName if necessary
	p, err := rFlat.ProfileName(ctx.Settings)
	if err == nil {
		rFlat.Profile = p
	}

	// save history
	ctx.Settings.Cache.AddHistory(utils.MakeRoleARN(rFlat.AccountId, rFlat.RoleName))
	if err := ctx.Settings.Cache.Save(false); err != nil {
		log.WithError(err).Warnf("Unable to update cache")
	}

	log.Debugf("%s", spew.Sdump(rFlat))
	return c.SubmitCreds(creds, rFlat.Profile, ctx.Cli.Ecs.Load.Slotted)
}

type EcsListCmd struct {
	Server string `kong:"help='Endpoint of aws-sso ECS Server',env='AWS_SSO_ECS_SERVER',default='localhost:4144'"`
}

// AfterApply determines if SSO auth token is required
func (l EcsListCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_NO_CONFIG
	return nil
}

func (cc *EcsListCmd) Run(ctx *RunContext) error {
	c := newClient(ctx.Cli.Ecs.Profile.Server, ctx)

	profiles, err := c.ListProfiles()
	if err != nil {
		return err
	}
	if len(profiles) == 0 {
		fmt.Printf("No profiles are stored in any named slots.\n")
		return nil
	}

	return listProfiles(profiles)
}

type EcsUnloadCmd struct {
	Profile string `kong:"short='p',help='Slot of AWS Profile to unload',predictor='profile'"`
	Server  string `kong:"help='Endpoint of aws-sso ECS Server',env='AWS_SSO_ECS_SERVER',default='localhost:4144'"`
}

// AfterApply determines if SSO auth token is required
func (l EcsUnloadCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_NO_CONFIG
	return nil
}

func (cc *EcsUnloadCmd) Run(ctx *RunContext) error {
	c := newClient(ctx.Cli.Ecs.Unload.Server, ctx)

	return c.Delete(ctx.Cli.Ecs.Unload.Profile)
}

func listProfiles(profiles []ecs.ListProfilesResponse) error {
	// sort our results
	sort.Slice(profiles, func(i, j int) bool {
		return strings.Compare(profiles[i].ProfileName, profiles[j].ProfileName) < 0
	})

	tr := []gotable.TableStruct{}
	for _, row := range profiles {
		tr = append(tr, row)
	}

	fields := []string{"ProfileName", "AccountIdPad", "RoleName", "Expires"}
	err := gotable.GenerateTable(tr, fields)
	if err != nil {
		fmt.Printf("\n")
	}

	return err
}

func newClient(server string, ctx *RunContext) *client.ECSClient {
	certChain, err := ctx.Store.GetEcsSslCert()
	if err != nil {
		log.Fatalf("Unable to get ECS SSL cert: %s", err)
	}
	bearerToken, err := ctx.Store.GetEcsBearerToken()
	if err != nil {
		log.Fatalf("Unable to get ECS bearer token: %s", err)
	}
	return client.NewECSClient(server, bearerToken, certChain)
}

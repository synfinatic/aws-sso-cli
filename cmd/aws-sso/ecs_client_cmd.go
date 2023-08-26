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
	"fmt"
	"sort"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	"github.com/synfinatic/aws-sso-cli/internal/ecs/client"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
	"github.com/synfinatic/aws-sso-cli/sso"
	"github.com/synfinatic/gotable"
)

type EcsListCmd struct{}

type EcsLoadCmd struct {
	// AWS Params
	Arn       string `kong:"short='a',help='ARN of role to assume',env='AWS_SSO_ROLE_ARN',predictor='arn'"`
	AccountId int64  `kong:"name='account',short='A',help='AWS AccountID of role to assume',env='AWS_SSO_ACCOUNT_ID',predictor='accountId',xor='account'"`
	Role      string `kong:"short='R',help='Name of AWS Role to assume',env='AWS_SSO_ROLE_NAME',predictor='role',xor='role'"`
	Profile   string `kong:"short='p',help='Name of AWS Profile to assume',predictor='profile',xor='account,role'"`

	// Other params
	Port    int  `kong:"help='TCP port of aws-sso ECS Server',env='AWS_SSO_ECS_PORT',default=4144"` // SEE ECS_PORT in ecs_cmd.go
	Slotted bool `kong:"short='s',help='Load credentials in a unique slot using the ProfileName as the key'"`
}

type EcsProfileCmd struct {
	Port int `kong:"help='TCP port of aws-sso ECS Server',env='AWS_SSO_ECS_PORT',default=4144"`
}

type EcsUnloadCmd struct {
	Port    int    `kong:"help='TCP port of aws-sso ECS Server',env='AWS_SSO_ECS_PORT',default=4144"`
	Profile string `kong:"short='p',help='Name of AWS Profile to unload',predictor='profile'"`
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
	c := client.NewECSClient(ctx.Cli.Ecs.Profile.Port)

	profile, err := c.GetProfile()
	if err != nil {
		return err
	}

	if profile.ProfileName == "" {
		return fmt.Errorf("No profile loaded in ECS Server.")
	}

	profiles := []ecs.ListProfilesResponse{
		profile,
	}
	return listProfiles(profiles)
}

func (cc *EcsUnloadCmd) Run(ctx *RunContext) error {
	c := client.NewECSClient(ctx.Cli.Ecs.Unload.Port)

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

	// save history
	ctx.Settings.Cache.AddHistory(utils.MakeRoleARN(rFlat.AccountId, rFlat.RoleName))
	if err := ctx.Settings.Cache.Save(false); err != nil {
		log.WithError(err).Warnf("Unable to update cache")
	}

	// do something
	c := client.NewECSClient(ctx.Cli.Ecs.Load.Port)

	log.Debugf("%s", spew.Sdump(rFlat))
	return c.SubmitCreds(creds, rFlat.Profile, ctx.Cli.Ecs.Load.Slotted)
}

func (cc *EcsListCmd) Run(ctx *RunContext) error {
	c := client.NewECSClient(ctx.Cli.Ecs.Profile.Port)

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

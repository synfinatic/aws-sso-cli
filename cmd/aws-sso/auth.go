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

	"github.com/synfinatic/aws-sso-cli/internal/awsconfig"
	"github.com/synfinatic/aws-sso-cli/internal/url"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
	"github.com/synfinatic/aws-sso-cli/sso"
)

type SelectCliArgs struct {
	Arn       string
	AccountId int64
	RoleName  string
	Profile   string
}

type InvalidArgsError struct {
	msg string
	arg string
}

func (e *InvalidArgsError) Error() string {
	if e.arg != "" {
		return fmt.Sprintf(e.msg, e.arg)
	}
	return fmt.Sprintf(e.msg)
}

type NoRoleSelectedError struct{}

func (e *NoRoleSelectedError) Error() string {
	return "Unable to select role"
}

func NewSelectCliArgs(arn string, accountId int64, role, profile string) *SelectCliArgs {
	return &SelectCliArgs{
		Arn:       arn,
		AccountId: accountId,
		RoleName:  role,
		Profile:   profile,
	}
}

func (a *SelectCliArgs) Update(ctx *RunContext) (*sso.AWSSSO, error) {
	if a.Profile != "" {
		awssso := doAuth(ctx)
		cache := ctx.Settings.Cache.GetSSO()
		rFlat, err := cache.Roles.GetRoleByProfile(a.Profile, ctx.Settings)
		if err != nil {
			return awssso, &InvalidArgsError{msg: "Invalid --profile %s", arg: a.Profile}
		}

		a.AccountId = rFlat.AccountId
		a.RoleName = rFlat.RoleName

		return awssso, nil
	}

	if a.Arn != "" {
		awssso := doAuth(ctx)
		accountId, role, err := utils.ParseRoleARN(a.Arn)
		if err != nil {
			return awssso, &InvalidArgsError{msg: "Invalid --arn %s", arg: a.Arn}
		}
		a.AccountId = accountId
		a.RoleName = role

		return awssso, nil
	}

	if a.AccountId != 0 && a.RoleName != "" {
		return doAuth(ctx), nil
	} else if a.AccountId != 0 || a.RoleName != "" {
		return &sso.AWSSSO{}, &InvalidArgsError{msg: "Must specify both --account and --role"}
	}

	return &sso.AWSSSO{}, &NoRoleSelectedError{}
}

// Creates a singleton AWSSO object post authentication
func doAuth(ctx *RunContext) *sso.AWSSSO {
	if AwsSSO != nil {
		return AwsSSO
	}
	s, err := ctx.Settings.GetSelectedSSO(ctx.Cli.SSO)
	if err != nil {
		log.Fatalf("%s", err.Error())
	}
	AwsSSO = sso.NewAWSSSO(s, &ctx.Store)
	err = AwsSSO.Authenticate(ctx.Settings.UrlAction, ctx.Settings.Browser)
	if err != nil {
		log.WithError(err).Fatalf("Unable to authenticate")
	}
	if err = ctx.Settings.Cache.Expired(s); err != nil {
		ssoName, err := ctx.Settings.GetSelectedSSOName(ctx.Cli.SSO)
		log.Infof("Refreshing AWS SSO role cache for %s, please wait...", ssoName)
		if err != nil {
			log.Fatalf(err.Error())
		}
		if err = ctx.Settings.Cache.Refresh(AwsSSO, s, ssoName); err != nil {
			log.WithError(err).Fatalf("Unable to refresh cache")
		}
		if err = ctx.Settings.Cache.Save(true); err != nil {
			log.WithError(err).Errorf("Unable to save cache")
		}

		// should we update our config??
		if !ctx.Cli.NoConfigCheck && ctx.Settings.AutoConfigCheck {
			if ctx.Settings.ConfigProfilesUrlAction != url.ConfigProfilesUndef {
				action, _ := url.NewAction(string(ctx.Settings.ConfigProfilesUrlAction))
				err := awsconfig.UpdateAwsConfig(ctx.Settings, action, "", true, false)
				if err != nil {
					log.Errorf("Unable to auto-update aws config file: %s", err.Error())
				}
			}
		}
	}
	return AwsSSO
}

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
	"github.com/synfinatic/aws-sso-cli/internal/utils"
	"github.com/synfinatic/aws-sso-cli/sso"
)

type LoginCmd struct {
	NoConfigCheck bool `kong:"help='Disable automatic ~/.aws/config updates'"`
	Threads       int  `kong:"help='Override number of threads for talking to AWS'"`
}

func (cc *LoginCmd) Run(ctx *RunContext) error {
	doAuth(ctx)

	log.Debugf("Checking the current active accounts vs. our cache")
	ssoAccounts, err := AwsSSO.GetAccounts()
	if err != nil {
		return err
	}

	ssoName, err := ctx.Settings.GetSelectedSSOName(ctx.Cli.SSO)
	if err != nil {
		log.Fatalf("%s", err.Error())
	}

	if ctx.Settings.Cache.SSO[ssoName] == nil {
		ctx.Settings.Cache.SSO[ssoName] = sso.NewSSOCache(ssoName)
	}

	needsRefresh := ctx.Settings.Cache.SSO[ssoName].NeedsRefresh(ctx.Settings.SSO[ssoName], ctx.Settings)

	if needsRefresh {
		log.Infof("Detected config file changes; automatically refreshing our cache...")
		c := &CacheCmd{
			NoConfigCheck: ctx.Cli.Login.NoConfigCheck,
			Threads:       ctx.Cli.Login.Threads,
		}
		if err = c.Run(ctx); err != nil {
			log.WithError(err).Errorf("Unable to refresh local cache")
		}
	}

	cachedAccounts := ctx.Settings.Cache.SSO[ssoName].Roles.Accounts

	delta := false
	if len(ssoAccounts) == len(cachedAccounts) {
		// make sure our cache has every account that SSO returns
		for _, accountInfo := range ssoAccounts {
			id, _ := utils.AccountIdToInt64(accountInfo.AccountId)
			if _, ok := cachedAccounts[id]; !ok {
				delta = true
			}
		}
	} else {
		delta = true
	}

	if delta {
		log.Infof("The AWS Accounts you have access to has changed.  Updating cache...")
		cache := CacheCmd{
			NoConfigCheck: cc.NoConfigCheck,
			Threads:       cc.Threads,
		}
		if err = cache.Run(ctx); err != nil {
			return err
		}
	}

	return nil
}

// checkAuth craetes a singleton AWSSO object and checks to see if
// we have a valid SSO authentication token.  If this is false, then
// we need to call doAuth()
func checkAuth(ctx *RunContext) bool {
	if AwsSSO == nil {
		s, err := ctx.Settings.GetSelectedSSO(ctx.Cli.SSO)
		if err != nil {
			log.Fatalf("%s", err.Error())
		}

		AwsSSO = sso.NewAWSSSO(s, &ctx.Store)
	}

	return AwsSSO.ValidAuthToken()
}

// doAuth creates a singleton AWSSO object post authentication
func doAuth(ctx *RunContext) {
	if checkAuth(ctx) {
		// nothing to do here
		log.Infof("You are already logged in. :)")
		return
	}

	err := AwsSSO.Authenticate(ctx.Settings.UrlAction, ctx.Settings.Browser)
	if err != nil {
		log.WithError(err).Fatalf("Unable to authenticate")
	}
}

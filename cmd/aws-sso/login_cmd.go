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
	"github.com/synfinatic/aws-sso-cli/internal/sso"
	"github.com/synfinatic/aws-sso-cli/internal/url"
)

type LoginCmd struct {
	UrlAction string `kong:"short='u',help='How to handle URLs [clip|exec|open|print|printurl|granted-containers|open-url-in-container] (default: open)'"`
	Threads   int    `kong:"help='Override number of threads for talking to AWS',default=${DEFAULT_THREADS}"`
}

// AfterApply determines if SSO auth token is required
func (l LoginCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_NO
	return nil
}

func (cc *LoginCmd) Run(ctx *RunContext) error {
	doAuth(ctx)
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

	action, err := url.NewAction(ctx.Cli.Login.UrlAction)
	if err != nil {
		log.Fatalf("Invalid --url-action %s", ctx.Cli.Login.UrlAction)
	}
	if action == "" {
		action = ctx.Settings.UrlAction
	}
	err = AwsSSO.Authenticate(action, ctx.Settings.Browser)
	if err != nil {
		log.WithError(err).Fatalf("Unable to authenticate")
	}

	s, err := ctx.Settings.GetSelectedSSO(ctx.Cli.SSO)
	if err != nil {
		log.Fatalf("%s", err.Error())
	}

	if err = ctx.Settings.Cache.Expired(s); err != nil {
		ssoName, err := ctx.Settings.GetSelectedSSOName(ctx.Cli.SSO)
		log.Infof("Refreshing AWS SSO role cache for %s, please wait...", ssoName)
		if err != nil {
			log.Fatalf(err.Error())
		}
		added, deleted, err := ctx.Settings.Cache.Refresh(AwsSSO, s, ssoName, ctx.Cli.Login.Threads)
		if err != nil {
			log.WithError(err).Fatalf("Unable to refresh cache")
		}

		if added > 0 || deleted > 0 {
			log.Infof("Updated cache: %d added, %d deleted", added, deleted)
		}

		if err = ctx.Settings.Cache.Save(true); err != nil {
			log.WithError(err).Errorf("Unable to save cache")
		}
	}
}

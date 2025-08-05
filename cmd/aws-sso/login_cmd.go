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
	"github.com/synfinatic/aws-sso-cli/internal/sso"
	"github.com/synfinatic/aws-sso-cli/internal/url"
)

type LoginCmd struct {
	UrlAction string `kong:"short='u',help='How to handle URLs [clip|exec|open|print|printurl|granted-containers|open-url-in-container|ansi-osc52] (default: open)',predictor='urlAction'"`
	Threads   int    `kong:"help='Override number of threads for talking to AWS',default=${DEFAULT_THREADS}"`
}

// AfterApply determines if SSO auth token is required
func (l LoginCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_SKIP
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
			log.Fatal("unable to select SSO", "sso", ctx.Cli.SSO, err.Error())
		}

		AwsSSO = sso.NewAWSSSO(s, ctx.Store)
	}

	return AwsSSO.ValidAuthToken()
}

// doAuth creates a singleton AWSSO object post authentication
func doAuth(ctx *RunContext) {
	if checkAuth(ctx) {
		// nothing to do here
		log.Info("You are already logged in. :)")
		return
	}

	var err error
	action := ctx.Settings.UrlAction // global default
	if len(ctx.Cli.Login.UrlAction) > 0 {
		// CLI override
		action, err = url.NewAction(ctx.Cli.Login.UrlAction)
		if err != nil {
			log.Fatal("Invalid --url-action", "action", ctx.Cli.Login.UrlAction)
		}
	} else if AwsSSO.SSOConfig.AuthUrlAction != url.Undef {
		// Auth specific override
		action = AwsSSO.SSOConfig.AuthUrlAction
	}
	err = AwsSSO.Authenticate(action, ctx.Settings.Browser)
	if err != nil {
		log.Fatal("Unable to authenticate", "error", err.Error())
	}

	s, err := ctx.Settings.GetSelectedSSO(ctx.Cli.SSO)
	if err != nil {
		log.Fatal("unable to select SSO", "sso", ctx.Cli.SSO, "error", err.Error())
	}

	if err = ctx.Settings.Cache.Expired(s); err != nil {
		ssoName, err := ctx.Settings.GetSelectedSSOName(ctx.Cli.SSO)
		if err != nil {
			log.Fatal("unable to GetSelectedSSOName", "sso", ctx.Cli.SSO, "error", err.Error())
		}
		log.Info("Refreshing AWS SSO role cache, please wait...", "sso", ssoName)
		added, deleted, err := ctx.Settings.Cache.Refresh(AwsSSO, s, ssoName, ctx.Cli.Login.Threads)
		if err != nil {
			log.Fatal("Unable to refresh cache", "error", err.Error())
		}

		if added > 0 || deleted > 0 {
			log.Info("Updated cache", "added", added, "deletd", deleted)
		}

		if err = ctx.Settings.Cache.Save(true); err != nil {
			log.Error("Unable to save cache", "error", err.Error())
		}
	}
}

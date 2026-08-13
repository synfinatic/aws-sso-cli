package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2026 Aaron Turner  <synfinatic at gmail dot com>
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
	ssoauth "github.com/synfinatic/aws-sso-cli/internal/sso/auth"
	"github.com/synfinatic/aws-sso-cli/internal/uri"
)

type LoginCmd struct {
	UrlAction string `kong:"short='u',help='How to handle URLs [clip|exec|open|print|printurl|granted-containers|open-url-in-container|ansi-osc52] (default: open)',predictor='urlAction'"`
	Threads   int    `kong:"help='Override number of threads for talking to AWS',default=${DEFAULT_THREADS}"`
	Force     bool   `kong:"short='f',help='End the current SSO session and start a new one, resetting the session duration'"`
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

// initAwsSSO creates the singleton AWSSSO object if it does not exist yet
func initAwsSSO(ctx *RunContext) *ssoauth.AWSSSO {
	if AwsSSO == nil {
		s, err := ctx.Settings.GetSelectedSSO(ctx.Cli.SSO)
		if err != nil {
			log.Fatal("unable to select SSO", "sso", ctx.Cli.SSO, err.Error())
		}

		AwsSSO = ssoauth.NewAWSSSO(s, ctx.Store)
	}

	return AwsSSO
}

// checkAuth creates a singleton AWSSO object and checks to see if
// we have a valid SSO authentication token.  If this is false, then
// we need to call doAuth()
func checkAuth(ctx *RunContext) bool {
	return initAwsSSO(ctx).ValidAuthToken(ctx.Ctx)
}

// endCurrentSession invalidates the current SSO sign-in session.  AWS reuses an
// active session and the new token inherits its expiry, so the session must be
// ended for the login which follows to reset the session duration.  STS
// credentials are left alone: IAM role sessions outlive the SSO session.
func endCurrentSession(ctx *RunContext, as *ssoauth.AWSSSO) {
	// Logout needs a valid AccessToken, so refresh an expired one first
	if !as.ValidAuthToken(ctx.Ctx) {
		log.Debug("no valid SSO token to log out with")
		return
	}

	if err := as.Logout(ctx.Ctx); err != nil {
		// not fatal: we fall back to re-authenticating into the existing session
		log.Warn("unable to end the current SSO session; the new token may inherit its expiry",
			"error", err.Error())
		return
	}

	// don't leave behind a token that looks valid locally but is dead server side
	if err := ctx.Store.DeleteCreateTokenResponse(ctx.Ctx, as.StoreKey()); err != nil {
		log.Debug("unable to delete invalidated token", "error", err.Error())
	}

	log.Debug("Ended the current SSO session", "storeKey", as.StoreKey())
}

// doAuth creates a singleton AWSSO object post authentication
func doAuth(ctx *RunContext) {
	as := initAwsSSO(ctx)

	if ctx.Cli.Login.Force {
		endCurrentSession(ctx, as)
	} else if checkAuth(ctx) {
		// nothing to do here
		log.Info("You are already logged in. :)")
		return
	}

	var err error
	action := ctx.Settings.UrlAction // global default
	if len(ctx.Cli.Login.UrlAction) > 0 {
		// CLI override
		action, err = uri.NewAction(ctx.Cli.Login.UrlAction)
		if err != nil {
			log.Fatal("Invalid --url-action", "action", ctx.Cli.Login.UrlAction)
		}
	} else if AwsSSO.SSOConfig.AuthUrlAction != uri.Undef {
		// Auth specific override
		action = AwsSSO.SSOConfig.AuthUrlAction
	}
	err = AwsSSO.Authenticate(ctx.Ctx, action, ctx.Settings.Browser)
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
		added, deleted, err := ctx.Settings.Cache.Refresh(AwsSSO, s, ssoName, ctx.Cli.Login.Threads, ctx.Settings)
		if err != nil {
			log.Fatal("Unable to refresh cache", "error", err.Error())
		}

		if len(added) > 0 || len(deleted) > 0 {
			log.Info("Updated cache", "added", len(added), "deleted", len(deleted))
		}

		if err = ctx.Settings.Cache.Save(true); err != nil {
			log.Error("Unable to save cache", "error", err.Error())
		}
	}
}

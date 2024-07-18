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
)

// LogoutCmd defines the Kong args for the flush command
type LogoutCmd struct{}

// AfterApply determines if SSO auth token is required
func (l LogoutCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_NO
	return nil
}

// Run executes the flush command
func (cc *LogoutCmd) Run(ctx *RunContext) error {
	var err error

	s, err := ctx.Settings.GetSelectedSSO(ctx.Cli.SSO)
	if err != nil {
		return err
	}
	awssso := sso.NewAWSSSO(s, &ctx.Store)

	flushSts(ctx, awssso)
	return awssso.Logout() // invalidate our AccessToken
}

// flushSts flushes our IAM STS Role credentials from the secure store
func flushSts(ctx *RunContext, awssso *sso.AWSSSO) {
	cache := ctx.Settings.Cache.GetSSO()
	for _, role := range cache.Roles.GetAllRoles() {
		if !role.IsExpired() {
			if err := ctx.Store.DeleteRoleCredentials(role.Arn); err != nil {
				log.WithError(err).Errorf("Unable to delete STS token for %s", role.Arn)
			}
		}
	}
	if err := ctx.Settings.Cache.MarkRolesExpired(); err != nil {
		log.Errorf(err.Error())
	} else {
		log.Infof("Deleted cached AWS STS credentials for %s", awssso.StoreKey())
	}
}

package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021 Aaron Turner  <synfinatic at gmail dot com>
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
	log "github.com/sirupsen/logrus"
	"github.com/synfinatic/aws-sso-cli/sso"
)

// FlushCmd defines the Kong args for the flush command
type FlushCmd struct {
	All bool `kong:"optional,name='all',help='Also flush individual STS tokens'"`
}

// Run executes the flush command
func (cc *FlushCmd) Run(ctx *RunContext) error {
	var err error

	s, err := ctx.Settings.GetSelectedSSO(ctx.Cli.SSO)
	if err != nil {
		return err
	}
	awssso := sso.NewAWSSSO(s.SSORegion, s.StartUrl, &ctx.Store)

	// Deleting the token response invalidates all our STS tokens
	err = ctx.Store.DeleteCreateTokenResponse(awssso.StoreKey())
	if err != nil {
		log.WithError(err).Errorf("Unable to delete TokenResponse")
	} else {
		log.Infof("Deleted cached Token for %s", awssso.StoreKey())
	}

	if ctx.Cli.Flush.All {
		for _, role := range ctx.Settings.Cache.Roles.GetAllRoles() {
			if !role.IsExpired() {
				if err = ctx.Store.DeleteRoleCredentials(role.Arn); err != nil {
					log.WithError(err).Errorf("Unable to delete STS token for %s", role.Arn)
				}
			}
		}
		err = ctx.Settings.Cache.MarkRolesExpired()
	}

	// Inform the cache the roles are expired
	return err
}

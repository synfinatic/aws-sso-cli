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
)

type FlushCmd struct {
	//	All bool `kong:"optional,name='all',help='Delete ClientData and SSO Token'"`
}

func (cc *FlushCmd) Run(ctx *RunContext) error {
	var err error

	sso := ctx.Config.SSO[ctx.Cli.SSO]
	awssso := NewAWSSSO(sso.SSORegion, sso.StartUrl, &ctx.Store)

	err = ctx.Store.DeleteCreateTokenResponse(awssso.StoreKey())
	if err != nil {
		log.WithError(err).Errorf("Unable to delete TokenResponse")
	} else {
		log.Infof("Deleted cached Token for %s", awssso.StoreKey())
	}
	/* XXX: Don't think this is actually useful
	if ctx.Cli.Expire.All {
		err = ctx.Store.DeleteRegisterClientData(awssso.StoreKey())
		if err != nil {
			log.WithError(err).Errorf("Unable to delete ClientData")
		} else {
			log.Infof("Deleted cached ClientData for %s", awssso.StoreKey())
		}
	}
	*/
	return nil
}

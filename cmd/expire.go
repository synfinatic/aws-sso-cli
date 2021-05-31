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

type ExpireCmd struct {
	All bool `kong:"optional,name='all',help='Expire ClientData and Token'"`
}

func (cc *ExpireCmd) Run(ctx *RunContext) error {
	var secureStore SecureStorage
	var err error

	if ctx.Cli.Store == "json" {
		secureStore, err = OpenJsonStore(GetPath(ctx.Cli.JsonStore))
		if err != nil {
			log.Panicf("Unable to open JSON Secure store: %s", err)
		}
	} else {
		log.Panicf("SecureStorage '%s' is not yet supported", ctx.Cli.Store)
	}

	awssso := NewAWSSSO(ctx.Sso.SSORegion, ctx.Sso.StartUrl, &secureStore)

	err = secureStore.DeleteCreateTokenResponse(awssso.StoreKey())
	if err != nil {
		log.WithError(err).Errorf("Unable to delete Token")
	} else {
		log.Infof("Deleted cached Token for %s", awssso.StoreKey())
	}
	if ctx.Cli.Expire.All {
		err = secureStore.DeleteRegisterClientData(awssso.StoreKey())
		if err != nil {
			log.WithError(err).Errorf("Unable to delete ClientData")
		} else {
			log.Infof("Deleted cached ClientData for %s", awssso.StoreKey())
		}
	}
	return nil
}

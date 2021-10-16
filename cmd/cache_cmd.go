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
	"fmt"

	log "github.com/sirupsen/logrus"
)

type CacheCmd struct{}

func (cc *CacheCmd) Run(ctx *RunContext) error {
	log.Info("Refreshing local cache...")

	awssso := doAuth(ctx)
	err := ctx.Cache.Refresh(awssso, ctx.Config.SSO[ctx.Cli.SSO])
	if err != nil {
		return fmt.Errorf("Unable to refresh role cache: %s", err.Error())
	}
	err = ctx.Cache.Save()
	if err != nil {
		return fmt.Errorf("Unable to save role cache: %s", err.Error())
	}

	log.Info("Cache has been refreshed.")
	return nil
}

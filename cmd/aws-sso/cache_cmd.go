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
)

type CacheCmd struct{}

func (cc *CacheCmd) Run(ctx *RunContext) error {
	s, err := ctx.Settings.GetSelectedSSO(ctx.Cli.SSO)
	if err != nil {
		log.Fatalf("%s", err.Error())
	}

	ssoName, err := ctx.Settings.GetSelectedSSOName(ctx.Cli.SSO)
	if err != nil {
		log.Fatalf(err.Error())
	}

	err = ctx.Settings.Cache.Refresh(AwsSSO, s, ssoName)
	if err != nil {
		return fmt.Errorf("Unable to refresh role cache: %s", err.Error())
	}
	ctx.Settings.Cache.PruneSSO(ctx.Settings)

	err = ctx.Settings.Cache.Save(true)
	if err != nil {
		return fmt.Errorf("Unable to save role cache: %s", err.Error())
	}

	return nil
}

package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2022 Aaron Turner  <synfinatic at gmail dot com>
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

	"github.com/synfinatic/aws-sso-cli/internal/helper"
	"github.com/willabides/kongplete"
)

type CompleteCmd struct {
	Install        bool `kong:"short='I',help='Install shell completions',xor='action'"`
	Uninstall      bool `kong:"short='U',help='Uninstall shell completions',xor='action'"`
	UninstallPre19 bool `kong:"help='Uninstall pre-v1.9 shell completion integration',xor='action'"`
}

func (cc *CompleteCmd) Run(ctx *RunContext) error {
	var err error

	if ctx.Cli.Completions.Install {
		// install the current auto-complete helper
		err = helper.InstallHelper()
	} else if ctx.Cli.Completions.Uninstall {
		// uninstall the current auto-complete helper
		err = helper.UninstallHelper()
	} else if ctx.Cli.Completions.UninstallPre19 {
		// install the old kongplete auto-complete helper
		kp := &kongplete.InstallCompletions{
			Uninstall: true,
		}
		err = kp.Run(ctx.Kctx)
	} else {
		err = fmt.Errorf("Please specify a valid flag")
	}

	if err == nil {
		log.Info("Please restart your shell for the changes to take effect")
	}
	return err
}

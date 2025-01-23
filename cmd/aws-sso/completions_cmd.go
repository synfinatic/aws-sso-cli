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
	"fmt"
	"os"

	"github.com/synfinatic/aws-sso-cli/internal/helper"
)

type CompleteCmd struct {
	Source      bool   `kong:"help='Print out completions for sourcing in the active shell',xor='action'"`
	Install     bool   `kong:"short='I',help='Install shell completions',xor='action'"`
	Uninstall   bool   `kong:"short='U',help='Uninstall shell completions',xor='action'"`
	Shell       string `kong:"help='Override detected shell'"`
	ShellScript string `kong:"help='Override file to (un)install shell completions'"`
}

// AfterApply determines if SSO auth token is required
func (c CompleteCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_SKIP
	return nil
}

func (cc *CompleteCmd) Run(ctx *RunContext) error {
	var err error

	if ctx.Cli.Setup.Completions.Source {
		return helper.NewSourceHelper(os.Executable, os.Stdout).Generate(ctx.Cli.Setup.Completions.Shell)
	} else if ctx.Cli.Setup.Completions.Install {
		// install the current auto-complete helper
		err = helper.InstallHelper(ctx.Cli.Setup.Completions.Shell, ctx.Cli.Setup.Completions.ShellScript)
	} else if ctx.Cli.Setup.Completions.Uninstall {
		// uninstall the current auto-complete helper
		err = helper.UninstallHelper(ctx.Cli.Setup.Completions.Shell, ctx.Cli.Setup.Completions.ShellScript)
	} else {
		err = fmt.Errorf("please specify a valid flag")
	}

	if err == nil {
		log.Info("please restart your shell for the changes to take effect")
	}
	return err
}

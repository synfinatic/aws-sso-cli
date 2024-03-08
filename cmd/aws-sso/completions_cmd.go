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
	"bytes"
	"fmt"
	"os"

	"github.com/synfinatic/aws-sso-cli/internal/helper"
	"github.com/willabides/kongplete"
)

type CompleteCmd struct {
	Source         bool   `kong:"help='Print out completions for sourcing in the active shell',xor='action'"`
	Install        bool   `kong:"short='I',help='Install shell completions',xor='action'"`
	Uninstall      bool   `kong:"short='U',help='Uninstall shell completions',xor='action'"`
	UninstallPre19 bool   `kong:"help='Uninstall pre-v1.9 shell completion integration',xor='action',xor='shell,script'"`
	Shell          string `kong:"help='Override detected shell',xor='shell'"`
	ShellScript    string `kong:"help='Override file to (un)install shell completions',xor='script'"`
}

func (cc *CompleteCmd) Run(ctx *RunContext) error {
	var err error

	if ctx.Cli.Completions.Source {
		err = helper.NewSourceHelper(os.Executable, os.Stdout).
			Generate(ctx.Cli.Completions.Shell)
	} else if ctx.Cli.Completions.Install {
		// install the current auto-complete helper
		err = helper.InstallHelper(ctx.Cli.Completions.Shell, ctx.Cli.Completions.ShellScript)
	} else if ctx.Cli.Completions.Uninstall {
		// uninstall the current auto-complete helper
		err = helper.UninstallHelper(ctx.Cli.Completions.Shell, ctx.Cli.Completions.ShellScript)
	} else if ctx.Cli.Completions.UninstallPre19 {
		// make sure we haven't installed our new completions first...
		if files := hasV19Installed(); len(files) == 0 {
			for _, f := range files {
				fmt.Printf("%s has the newer shell completions\n", f)
			}
			return fmt.Errorf("unable to automatically uninstall pre-1.9 shell completions")
		}

		// Uninstall the old kongplete auto-complete helper
		kp := &kongplete.InstallCompletions{
			Uninstall: true,
		}
		err = kp.Run(ctx.Kctx)
	} else {
		err = fmt.Errorf("please specify a valid flag")
	}

	if err == nil {
		log.Info("please restart your shell for the changes to take effect")
	}
	return err
}

// hasV19Installed returns the paths to any shell script we manage
// that has the old < v1.9 completions installed or an empty list
// if none exist.
func hasV19Installed() []string {
	ret := []string{}
	for _, f := range helper.ConfigFiles() {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if bytes.Contains(b, []byte("# BEGIN_AWS_SSO_CLI\n")) {
			ret = append(ret, f)
		}
	}

	return ret
}

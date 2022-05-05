package helper

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
	"os"
	"path"

	"github.com/riywo/loginshell"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

import _ "embed"

//go:embed bash_profile.sh
var BASH_PROFILE string

//go:embed zshrc.sh
var ZSH_SCRIPT string

//go:embed aws-sso.fish
var FISH_SCRIPT string

// map of shells to their file we edit by default
var SHELL_SCRIPTS = map[string]string{
	"bash": "~/.bash_profile",
	"zsh":  "~/.zshrc",
	"fish": getFishScript(),
}

// ConfigFiles returns a list of all the config files we might edit
func ConfigFiles() []string {
	ret := []string{}

	for _, v := range SHELL_SCRIPTS {
		ret = append(ret, utils.GetHomePath(v))
	}
	return ret
}

// InstallHelper installs any helper code into our shell startup script(s)
func InstallHelper(shell, script string) error {
	var err error
	var ok bool
	var shellFile string

	if shell == "" {
		if shell, err = detectShell(); err != nil {
			return err
		}
	}

	if script == "" {
		if shellFile, ok = SHELL_SCRIPTS[shell]; !ok {
			return fmt.Errorf("unsupported shell: %s", shell)
		}
		script = utils.GetHomePath(shellFile)
	}

	switch shell {
	case "bash":
		err = installConfigFile(script, BASH_PROFILE)
	case "zsh":
		err = installConfigFile(script, ZSH_SCRIPT)
	case "fish":
		err = installConfigFile(script, FISH_SCRIPT)
	default:
		err = fmt.Errorf("unsupported shell: %s", shell)
	}

	return err
}

// UninstallHelper removes any helper code from our shell startup script(s)
func UninstallHelper(shell, script string) error {
	var err error
	var ok bool
	var shellFile string

	if shell == "" {
		if shell, err = detectShell(); err != nil {
			return err
		}
	}

	if script == "" {
		if shellFile, ok = SHELL_SCRIPTS[shell]; !ok {
			return fmt.Errorf("unsupported shell: %s", shell)
		}
		script = utils.GetHomePath(shellFile)
	}

	switch shell {
	case "bash":
		err = uninstallConfigFile(script, BASH_PROFILE)
	default:
		err = fmt.Errorf("unsupported shell: %s", shell)
	}

	return err
}

// installConfigFile adds our blob to the given file
func installConfigFile(path, contents string) error {
	var err error
	var exec string
	var fe *utils.FileEdit

	if exec, err = os.Executable(); err != nil {
		return err
	}

	args := map[string]string{
		"Executable": exec,
	}

	if fe, err = utils.NewFileEdit(BASH_PROFILE, args); err != nil {
		return err
	}

	if err = fe.UpdateConfig(false, false, path); err != nil {
		return err
	}

	return nil
}

// uninstallConfigFile removes our blob from the given file
func uninstallConfigFile(path, contents string) error {
	var err error
	var fe *utils.FileEdit

	if fe, err = utils.NewFileEdit("", ""); err != nil {
		return nil
	}

	if err = fe.UpdateConfig(false, false, path); err != nil {
		log.Warnf("unable to remove config: %s", err.Error())
	}

	return nil
}

// detectShell returns the name of our current shell
func detectShell() (string, error) {
	var shellPath string
	var err error

	if shellPath, err = loginshell.Shell(); err != nil {
		return "", err
	}

	_, shell := path.Split(shellPath)
	return shell, nil
}

// returns the location of our fish completion script
func getFishScript() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = utils.GetHomePath("~/.config")
	}

	return path.Join(base, "fish", "completions", "aws-sso.fish")
}

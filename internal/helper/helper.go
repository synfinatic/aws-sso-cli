package helper

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
	"embed"
	"fmt"
	"os"
	"path"

	"github.com/riywo/loginshell"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

//go:embed bash_profile.sh zshrc.sh aws-sso.fish
var embedFiles embed.FS

type fileMap struct {
	Key  string
	Path string
}

// map of shells to their file we edit by default
var SHELL_SCRIPTS = map[string]fileMap{
	"bash": {
		Key:  "bash_profile.sh",
		Path: "~/.bash_profile",
	},
	"zsh": {
		Key:  "zshrc.sh",
		Path: "~/.zshrc",
	},
	"fish": {
		Key:  "aws-sso.fish",
		Path: getFishScript(),
	},
}

// ConfigFiles returns a list of all the config files we might edit
func ConfigFiles() []string {
	ret := []string{}

	for _, v := range SHELL_SCRIPTS {
		ret = append(ret, utils.GetHomePath(v.Path))
	}
	return ret
}

// getScript takes a shell and returns the contents & path to the shell script
func getScript(shell string) ([]byte, string, error) {
	var err error
	var bytes []byte
	var shellFile fileMap
	var ok bool

	if shell == "" {
		if shell, err = detectShell(); err != nil {
			return bytes, "", err
		}
	}
	log.Debugf("using %s as our shell", shell)

	if shellFile, ok = SHELL_SCRIPTS[shell]; !ok {
		return bytes, "", fmt.Errorf("unsupported shell: %s", shell)
	}

	path := utils.GetHomePath(shellFile.Path)
	bytes, err = embedFiles.ReadFile(shellFile.Key)
	if err != nil {
		return bytes, "", err
	}
	return bytes, path, nil
}

// InstallHelper installs any helper code into our shell startup script(s)
func InstallHelper(shell string, path string) error {
	c, defaultPath, err := getScript(shell)
	if err != nil {
		return err
	}

	if path == "" {
		err = installConfigFile(defaultPath, c)
	} else {
		err = installConfigFile(path, c)
	}

	return err
}

// UninstallHelper removes any helper code from our shell startup script(s)
func UninstallHelper(shell string, path string) error {
	c, defaultPath, err := getScript(shell)
	if err != nil {
		return err
	}

	if path == "" {
		err = uninstallConfigFile(defaultPath, c)
	} else {
		err = uninstallConfigFile(path, c)
	}
	return err
}

// installConfigFile adds our blob to the given file
func installConfigFile(path string, contents []byte) error {
	var err error
	var exec string
	var fe *utils.FileEdit

	if exec, err = os.Executable(); err != nil {
		return err
	}

	args := map[string]string{
		"Executable": exec,
	}

	if fe, err = utils.NewFileEdit(string(contents), args); err != nil {
		return err
	}

	if err = fe.UpdateConfig(false, false, path); err != nil {
		return err
	}

	return nil
}

// uninstallConfigFile removes our blob from the given file
func uninstallConfigFile(path string, contents []byte) error {
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
	log.Debugf("detected configured shell as: %s", shell)
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

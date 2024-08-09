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
	"bytes"
	"embed"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/riywo/loginshell"
	"github.com/synfinatic/aws-sso-cli/internal/logger"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

var log logger.CustomLogger

func init() {
	log = logger.GetLogger()
}

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
	log.Debug("detected our shell", "shell", shell)

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

type SourceHelper struct {
	getExe func() (string, error)
	output io.Writer
}

// NewSourceHelper returns a new SourceHelper and takes a function
// to get the current executable path and an io.Writer to write the output to
func NewSourceHelper(getExe func() (string, error), output io.Writer) *SourceHelper {
	return &SourceHelper{
		getExe: os.Executable,
		output: os.Stdout,
	}
}

// SourceHelper can be used to generate the completions script for immediate sourcing in the active shell
func (h SourceHelper) Generate(shell string) error {
	c, _, err := getScript(shell)
	if err != nil {
		return err
	}

	execPath, err := h.getExe()
	if err != nil {
		return err
	}

	return printConfig(c, execPath, h.output)
}

var forceIt bool = false // used just for testing

// InstallHelper installs any helper code into our shell startup script(s)
func InstallHelper(shell string, path string) error {
	c, defaultPath, err := getScript(shell)
	if err != nil {
		return err
	}

	if path == "" {
		err = installConfigFile(defaultPath, c, forceIt)
	} else {
		err = installConfigFile(path, c, forceIt)
	}

	return err
}

// UninstallHelper removes any helper code from our shell startup script(s)
func UninstallHelper(shell string, path string) error {
	_, defaultPath, err := getScript(shell)
	if err != nil {
		return err
	}

	if path == "" {
		err = uninstallConfigFile(defaultPath)
	} else {
		err = uninstallConfigFile(path)
	}
	return err
}

// printConfig writes the given template to the output
// It will replace any variables in the file with the given args
func printConfig(template []byte, execPath string, output io.Writer) error {
	var err error
	var fileContents []byte

	args := map[string]string{
		"Executable": execPath,
	}

	// generate the source with the given args using the template
	if fileContents, err = utils.GenerateSource(string(template), args); err != nil {
		return err
	}
	if len(fileContents) == 0 {
		return fmt.Errorf("no data generated")
	}

	len, err := io.Copy(output, bytes.NewReader(fileContents))
	if len == 0 {
		return fmt.Errorf("no data written to output")
	}
	return err
}

// installConfigFile adds our blob to the given file
func installConfigFile(path string, contents []byte, force bool) error {
	var err error
	var exec string
	var fe *utils.FileEdit

	if exec, err = os.Executable(); err != nil {
		return err
	}

	args := map[string]string{
		"Executable": exec,
	}

	if fe, err = utils.NewFileEdit(string(contents), "", args); err != nil {
		return err
	}

	_, _, err = fe.UpdateConfig(false, force, path)
	if err != nil {
		return err
	}

	return nil
}

// uninstallConfigFile removes our blob from the given file
func uninstallConfigFile(path string) error {
	var err error
	var fe *utils.FileEdit

	if fe, err = utils.NewFileEdit("", "", ""); err != nil {
		return nil
	}

	_, _, err = fe.UpdateConfig(false, false, path)
	if err != nil {
		log.Warn("unable to remove config", "error", err.Error())
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
	log.Debug("detected our shell", "shell", shell)
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

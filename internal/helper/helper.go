package helper

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2026 Aaron Turner  <synfinatic at gmail dot com>
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
	"github.com/synfinatic/aws-sso-cli/internal/fileutils"
	"github.com/synfinatic/aws-sso-cli/internal/logger"
	"github.com/synfinatic/flexlog"
)

var log flexlog.FlexLogger

func init() {
	log = logger.GetLogger()
}

//go:embed bash_profile.sh zshrc.sh fish
var embedFiles embed.FS

type fileMap struct {
	Key  string
	Path string
}

// map of single-file shells to their config file
var SHELL_SCRIPTS = map[string]fileMap{
	"bash": {
		Key:  "bash_profile.sh",
		Path: "~/.bash_profile",
	},
	"zsh": {
		Key:  "zshrc.sh",
		Path: "~/.zshrc",
	},
}

type fishFileSpec struct {
	Key  string // embedded path, e.g. "fish/aws-sso.fish"
	Dir  string // "completions" or "functions"
	Name string // target filename
}

// FISH_FILES defines the four files installed for fish shell support.
// Paths are resolved lazily at call time via getFishBase() so that
// XDG_CONFIG_HOME overrides work correctly in tests.
var FISH_FILES = []fishFileSpec{
	{Key: "fish/aws-sso.fish", Dir: "completions", Name: "aws-sso.fish"},
	{Key: "fish/aws-sso-profile.fish", Dir: "functions", Name: "aws-sso-profile.fish"},
	{Key: "fish/aws-sso-profile-comp.fish", Dir: "completions", Name: "aws-sso-profile.fish"},
	{Key: "fish/aws-sso-clear.fish", Dir: "functions", Name: "aws-sso-clear.fish"},
}

// shellScript holds an embedded template's contents and its resolved target path.
type shellScript struct {
	contents []byte
	path     string
}

// ConfigFiles returns a list of all the config files we might edit
func ConfigFiles() []string {
	ret := []string{}

	for _, v := range SHELL_SCRIPTS {
		ret = append(ret, fileutils.GetHomePath(v.Path))
	}

	base := getFishBase()
	for _, f := range FISH_FILES {
		ret = append(ret, path.Join(base, f.Dir, f.Name))
	}

	return ret
}

// getScripts returns all (contents, resolved-path) pairs for a shell.
// Handles shell auto-detection when shell == "".
func getScripts(shell string) ([]shellScript, error) {
	var err error

	if shell == "" {
		if shell, err = detectShell(); err != nil {
			return nil, err
		}
	}
	log.Debug("detected our shell", "shell", shell)

	if shell == "fish" {
		base := getFishBase()
		var result []shellScript
		for _, f := range FISH_FILES {
			c, err := embedFiles.ReadFile(f.Key)
			if err != nil {
				return nil, err
			}
			result = append(result, shellScript{
				contents: c,
				path:     path.Join(base, f.Dir, f.Name),
			})
		}
		return result, nil
	}

	shellFile, ok := SHELL_SCRIPTS[shell]
	if !ok {
		return nil, fmt.Errorf("unsupported shell: %s", shell)
	}

	c, err := embedFiles.ReadFile(shellFile.Key)
	if err != nil {
		return nil, err
	}
	return []shellScript{{contents: c, path: fileutils.GetHomePath(shellFile.Path)}}, nil
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
	scripts, err := getScripts(shell)
	if err != nil {
		return err
	}

	execPath, err := h.getExe()
	if err != nil {
		return err
	}

	for _, s := range scripts {
		if err = printConfig(s.contents, execPath, h.output); err != nil {
			return err
		}
	}
	return nil
}

var forceIt bool = false // used just for testing

// InstallHelper installs any helper code into our shell startup script(s)
func InstallHelper(shell string, overridePath string) error {
	scripts, err := getScripts(shell)
	if err != nil {
		return err
	}

	for i, s := range scripts {
		target := s.path
		if overridePath != "" && i == 0 {
			target = overridePath
		}
		if err = installConfigFile(target, s.contents, forceIt); err != nil {
			return err
		}
	}
	return nil
}

// UninstallHelper removes any helper code from our shell startup script(s)
func UninstallHelper(shell string, overridePath string) error {
	resolved := shell
	if resolved == "" {
		var err error
		if resolved, err = detectShell(); err != nil {
			return err
		}
	}

	scripts, err := getScripts(resolved)
	if err != nil {
		return err
	}

	for i, s := range scripts {
		target := s.path
		if overridePath != "" && i == 0 {
			target = overridePath
		}
		if resolved == "fish" {
			if err := os.Remove(target); err != nil && !os.IsNotExist(err) { // nolint:gosec
				log.Warn("unable to remove fish config", "file", target, "error", err.Error())
			}
		} else {
			if err := uninstallConfigFile(target); err != nil {
				log.Warn("unable to remove config", "file", target, "error", err.Error())
			}
		}
	}
	return nil
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
	if fileContents, err = fileutils.GenerateSource(string(template), args); err != nil {
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
	var fe *fileutils.FileEdit

	if exec, err = os.Executable(); err != nil {
		return err
	}

	args := map[string]string{
		"Executable": exec,
	}

	if fe, err = fileutils.NewFileEdit(string(contents), "", args); err != nil {
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
	var fe *fileutils.FileEdit

	if fe, err = fileutils.NewFileEdit("", "", ""); err != nil {
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

// getFishBase returns the base fish config directory, honouring XDG_CONFIG_HOME
func getFishBase() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = fileutils.GetHomePath("~/.config")
	}
	return path.Join(base, "fish")
}

// getFishCompletionPath returns the path for a fish completion file
func getFishCompletionPath(name string) string {
	return path.Join(getFishBase(), "completions", name)
}

// getFishFunctionPath returns the path for a fish function file
func getFishFunctionPath(name string) string {
	return path.Join(getFishBase(), "functions", name)
}

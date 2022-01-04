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
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"text/template"

	"github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/hexops/gotextdiff/span"
	log "github.com/sirupsen/logrus"
	"github.com/synfinatic/aws-sso-cli/utils"
)

const (
	AWS_CONFIG_FILE = "~/.aws/config"
	CONFIG_PREFIX   = "# BEGIN_AWS_SSO_CLI"
	CONFIG_SUFFIX   = "# END_AWS_SSO_CLI"
	CONFIG_TEMPLATE = `
{{ .Prefix }}
{{ range .Profiles }}
[profile {{ .Profile }}]
credential_process = {{ .BinaryPath }} -u open -S "{{ .Sso }}" process --arn {{ .Arn }}
output={{ .Output }}
{{end}}
{{ .Suffix }}
`
)

type TemplateConfig struct {
	Prefix   string
	Suffix   string
	Profiles []ProfileConfig
}

type ProfileConfig struct {
	Sso        string
	Arn        string
	Profile    string
	Output     string
	BinaryPath string
}

type ConfigCmd struct {
	Print  bool   `kong:"help='Print profile entries instead of modifying config file',xor='action'"`
	Diff   bool   `kong:"help='Print a diff of the new config file instead of modifying it',xor='action'"`
	Output string `kong:"help='Output format [json|yaml|yaml-stream|text|table]',default='json',enum='json,yaml,yaml-stream,text,table'"`
}

func (cc *ConfigCmd) Run(ctx *RunContext) error {
	set := ctx.Settings
	binaryPath, _ := os.Executable()

	// Find all the roles across all of the SSO instances
	profiles := []ProfileConfig{}
	for ssoName, s := range set.Cache.SSO {
		for _, role := range s.Roles.GetAllRoles() {
			profile, err := role.ProfileName(ctx.Settings)
			if err != nil {
				log.Errorf("Unable to generate profile name for %s: %s", role.Arn, err.Error())
			}
			profiles = append(profiles, ProfileConfig{
				Sso:        ssoName,
				Arn:        role.Arn,
				Profile:    profile,
				Output:     ctx.Cli.Config.Output,
				BinaryPath: binaryPath,
			})
		}
	}

	templ, err := template.New("profile").Parse(CONFIG_TEMPLATE)
	if err != nil {
		return err
	}

	config := TemplateConfig{
		Prefix:   CONFIG_PREFIX,
		Suffix:   CONFIG_SUFFIX,
		Profiles: profiles,
	}

	if ctx.Cli.Config.Print {
		if err := templ.Execute(os.Stdout, config); err != nil {
			return err
		}
	}
	return updateConfig(ctx, templ, profiles)
}

func updateConfig(ctx *RunContext, templ *template.Template, profiles []ProfileConfig) error {
	// open our config file
	configFile := awsConfigFile()
	input, err := os.Open(configFile)
	if err != nil {
		return err
	}

	// open a temp file
	tfile, err := os.CreateTemp("", "config.*")
	tempFileName := tfile.Name()
	if err != nil {
		return err
	}

	w := bufio.NewWriter(tfile)

	config := TemplateConfig{
		Profiles: profiles,
		Prefix:   CONFIG_PREFIX,
		Suffix:   CONFIG_SUFFIX,
	}

	// read & write up to the prefix
	r := bufio.NewReader(input)

	line, err := r.ReadString('\n')
	for err == nil && line != CONFIG_PREFIX {
		if _, err = w.WriteString(line); err != nil {
			return err
		}
		line, err = r.ReadString('\n')
	}

	endOfFile := false
	if err != nil && err != io.EOF {
		return err
	} else if err == io.EOF {
		// Reached EOF before finding our CONFIG_PREFIX
		endOfFile = true
	}

	// write our template out
	if err = templ.Execute(w, config); err != nil {
		return err
	}

	if !endOfFile {
		line, err = r.ReadString('\n')
		// consume our entries and the suffix
		for err == nil && line != CONFIG_SUFFIX {
			line, err = r.ReadString('\n')
		}

		// if not EOF or other error, read & write the config until EOF
		if err == nil {
			// read until error
			line, err = r.ReadString('\n')
			for err == nil {
				if _, err = w.WriteString(line); err != nil {
					return err
				}
				line, err = r.ReadString('\n')
			}
			if err != io.EOF {
				return err
			}
		}
	}
	w.Flush()
	tfile.Close()
	input.Close()

	aBytes, err := ioutil.ReadFile(configFile)
	if err != nil {
		return err
	}
	bBytes, err := ioutil.ReadFile(tempFileName)
	if err != nil {
		return err
	}
	if ctx.Cli.Config.Diff {
		edits := myers.ComputeEdits(span.URIFromPath(configFile), string(aBytes), string(bBytes))
		fmt.Printf("%s", gotextdiff.ToUnified(configFile, tempFileName, string(aBytes), edits))
	} else {
		return fmt.Errorf("Writing a new config file is not yet supported")
	}
	return nil
}

// awsConfigFile returns the path the the users ~/.aws/config
func awsConfigFile() string {
	// did user set the value?
	path := os.Getenv("AWS_CONFIG_FILE")
	if path == "" {
		path = utils.GetHomePath(AWS_CONFIG_FILE)
	}
	log.Debugf("path = %s", path)
	return path
}

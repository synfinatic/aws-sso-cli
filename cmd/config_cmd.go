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
	"github.com/synfinatic/aws-sso-cli/utils"
)

const (
	AWS_CONFIG_FILE = "~/.aws/config"
	CONFIG_PREFIX   = "# BEGIN_AWS_SSO_CLI"
	CONFIG_SUFFIX   = "# END_AWS_SSO_CLI"
	CONFIG_TEMPLATE = `# BEGIN_AWS_SSO_CLI
{{ range $sso, $struct := . }}{{ range $arn, $profile := $struct }}
[profile {{ $profile.Profile }}]
credential_process = {{ $profile.BinaryPath }} -u {{ $profile.Open }} -S "{{ $profile.Sso }}" process --arn {{ $profile.Arn }}
{{ range $key, $value := $profile.ConfigVariables }}{{ $key }} = {{ $value }}
{{end}}{{end}}{{end}}
# END_AWS_SSO_CLI
`
)

type ProfileMap map[string]map[string]ProfileConfig

type ProfileConfig struct {
	Arn             string
	BinaryPath      string
	ConfigVariables map[string]interface{}
	Open            string
	Profile         string
	Sso             string
}

type ConfigCmd struct {
	Diff  bool   `kong:"help='Print a diff of changes to the config file instead of modifying it'"`
	Open  string `kong:"help='Override how to open URLs: [open|clip]',required"`
	Print bool   `kong:"help='Print profile entries instead of modifying config file',xor='action'"`
}

func (cc *ConfigCmd) Run(ctx *RunContext) error {
	set := ctx.Settings
	binaryPath, err := os.Executable()
	if err != nil {
		return err
	}

	profiles := ProfileMap{}
	profileUniqueCheck := map[string][]string{} // ProfileName() => Arn

	// Find all the roles across all of the SSO instances
	for ssoName, s := range set.Cache.SSO {
		for _, role := range s.Roles.GetAllRoles() {
			profile, err := role.ProfileName(ctx.Settings)
			if err != nil {
				log.Errorf("Unable to generate profile name for %s: %s", role.Arn, err.Error())
			}

			if match, duplicate := profileUniqueCheck[profile]; duplicate {
				return fmt.Errorf("Duplicate profile name '%s' for:\n%s: %s\n%s: %s",
					profile, match[0], match[1], ssoName, role.Arn)
			}
			profileUniqueCheck[profile] = []string{ssoName, role.Arn}

			if _, ok := profiles[ssoName]; !ok {
				profiles[ssoName] = map[string]ProfileConfig{}
			}

			profiles[ssoName][role.Arn] = ProfileConfig{
				Arn:             role.Arn,
				BinaryPath:      binaryPath,
				ConfigVariables: ctx.Settings.ConfigVariables,
				Open:            ctx.Cli.Config.Open,
				Profile:         profile,
				Sso:             ssoName,
			}
		}
	}

	templ, err := template.New("profile").Parse(CONFIG_TEMPLATE)
	if err != nil {
		return err
	}

	if ctx.Cli.Config.Print {
		if err := templ.Execute(os.Stdout, profiles); err != nil {
			return err
		}
	}
	return updateConfig(ctx, templ, profiles)
}

// updateConfig calculates the diff
func updateConfig(ctx *RunContext, templ *template.Template, profiles ProfileMap) error {
	// open our config file
	configFile := awsConfigFile()
	input, err := os.Open(configFile)
	if err != nil {
		return err
	}

	// open a temp file
	output, err := os.CreateTemp("", "config.*")
	if err != nil {
		return err
	}
	tempFileName := output.Name()
	defer os.Remove(tempFileName)

	w := bufio.NewWriter(output)

	// read & write up to the prefix
	r := bufio.NewReader(input)

	line, err := r.ReadString('\n')
	for err == nil && line != fmt.Sprintf("%s\n", CONFIG_PREFIX) {
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
	if err = templ.Execute(w, profiles); err != nil {
		return err
	}

	if !endOfFile {
		line, err = r.ReadString('\n')
		// consume our entries and the suffix
		for err == nil && line != fmt.Sprintf("%s\n", CONFIG_SUFFIX) {
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
	output.Close()
	input.Close()

	diff, err := generateDiff(configFile, tempFileName)
	if err != nil {
		return err
	}

	if len(diff) == 0 {
		// do nothing if there is no diff
		log.Infof("No changes to made to %s", configFile)
		return nil
	}

	if ctx.Cli.Config.Diff {
		fmt.Printf("%s", diff)
		return nil
	}

	// copy file into place
	input, err = os.Open(tempFileName) // output/tempFile is now the input!
	if err != nil {
		return err
	}
	output, err = os.OpenFile(configFile, os.O_RDWR|os.O_CREATE, 0600) // ~/.aws/config is now the output
	if err != nil {
		return err
	}
	_, err = io.Copy(output, input)
	return err
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

// generateDiff generates a diff between two files.  Takes two file names as inputs
func generateDiff(aFile, bFile string) (string, error) {
	// open the files fresh for the diff
	aBytes, err := ioutil.ReadFile(aFile)
	if err != nil {
		return "", err
	}
	bBytes, err := ioutil.ReadFile(bFile)
	if err != nil {
		return "", err
	}
	edits := myers.ComputeEdits(span.URIFromPath(aFile), string(aBytes), string(bBytes))
	diff := fmt.Sprintf("%s", gotextdiff.ToUnified(aFile, bFile, string(aBytes), edits))
	log.Debugf("diff:\n%s", diff)
	return diff, nil
}

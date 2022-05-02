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
	"bytes"
	"fmt"
	"io"
	"os"
	"text/template"

	"github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/hexops/gotextdiff/span"
	"github.com/manifoldco/promptui"
	"github.com/synfinatic/aws-sso-cli/sso"
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

var VALID_CONIFG_OPEN []string = []string{
	"clip",
	"exec",
	"open",
}

type ConfigCmd struct {
	Diff  bool   `kong:"help='Print a diff of changes to the config file instead of modifying it'"`
	Open  string `kong:"help='Specify how to open URLs: [clip|exec|open]'"`
	Print bool   `kong:"help='Print profile entries instead of modifying config file'"`
	Force bool   `kong:"help='Write a new config file without prompting'"`
}

func (cc *ConfigCmd) Run(ctx *RunContext) error {
	open := ctx.Settings.ConfigUrlAction
	if utils.StrListContains(ctx.Cli.Config.Open, VALID_CONIFG_OPEN) {
		open = ctx.Cli.Config.Open
	}

	if len(open) == 0 {
		return fmt.Errorf("Please specify --open [clip|exec|open]")
	}

	profiles, err := ctx.Settings.GetAllProfiles(open)
	if err != nil {
		return err
	}

	if err := profiles.UniqueCheck(ctx.Settings); err != nil {
		return err
	}

	templ := configTemplate()

	if ctx.Cli.Config.Print {
		return templ.Execute(os.Stdout, profiles)
	}
	return updateConfig(ctx, templ, profiles)
}

// generateNewFile generates the contents of a new config file
func generateNewFile(ctx *RunContext, templ *template.Template, profiles *sso.ProfileMap) ([]byte, error) {
	var output bytes.Buffer
	w := bufio.NewWriter(&output)

	// read & write up to the prefix
	configFile := awsConfigFile()
	input, err := os.Open(configFile) // output/tempFile is now the input!
	if err != nil {
		return []byte{}, err
	}
	defer input.Close()

	r := bufio.NewReader(input)

	line, err := r.ReadString('\n')
	for err == nil && line != fmt.Sprintf("%s\n", CONFIG_PREFIX) {
		if _, err = w.WriteString(line); err != nil {
			return []byte{}, err
		}
		line, err = r.ReadString('\n')
	}

	endOfFile := false
	if err != nil && err != io.EOF {
		return []byte{}, err
	} else if err == io.EOF {
		// Reached EOF before finding our CONFIG_PREFIX
		endOfFile = true
	}

	// write our template out
	if err = templ.Execute(w, profiles); err != nil {
		return []byte{}, err
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
					return []byte{}, err
				}
				line, err = r.ReadString('\n')
			}
			if err != io.EOF {
				return []byte{}, err
			}
		}
	}
	w.Flush()

	return output.Bytes(), nil
}

func configTemplate() *template.Template {
	templ, err := template.New("profile").Parse(CONFIG_TEMPLATE)
	if err != nil {
		log.Panicf("Unable to parse config template: %s", err.Error())
	}

	return templ
}

// updateConfig calculates the diff
func updateConfig(ctx *RunContext, templ *template.Template, profiles *sso.ProfileMap) error {
	// open our config file
	configFile := awsConfigFile()
	inputBytes, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}

	outputBytes, err := generateNewFile(ctx, templ, profiles)
	if err != nil {
		return err
	}

	diff, err := diffBytes(inputBytes, outputBytes, configFile, "new_config.yaml")
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

	if !ctx.Cli.Config.Force {
		fmt.Printf("The following changes are proposed to %s:\n%s\n\n",
			utils.GetHomePath("~/.aws/config"), diff)
		label := "Modify config file with proposed changes?"
		sel := promptui.Select{
			Label:        label,
			Items:        []string{"No", "Yes"},
			HideSelected: false,
			Stdout:       &bellSkipper{},
			Templates: &promptui.SelectTemplates{
				Selected: fmt.Sprintf(`%s: {{ . | faint }}`, label),
			},
		}

		_, val, err := sel.Run()
		if err != nil {
			return err
		}

		if val != "Yes" {
			fmt.Printf("Aborting.")
			return nil
		}
	}

	return os.WriteFile(configFile, outputBytes, 0600)
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

// diffBytes generates a diff between two byte arrays
func diffBytes(aBytes, bBytes []byte, aName, bName string) (string, error) {
	edits := myers.ComputeEdits(span.URIFromPath(aName), string(aBytes), string(bBytes))
	diff := gotextdiff.ToUnified(aName, bName, string(aBytes), edits)
	log.Debugf("diff:\n%v", diff)
	return fmt.Sprintf("%s", diff), nil
}

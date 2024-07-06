package utils

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
)

const (
	DEFAULT_SSO_NAME = "Default" // DefaultSSO per cmd/aws-sso/main.go
	CONFIG_PREFIX    = "# BEGIN_AWS_SSO_CLI"
	CONFIG_SUFFIX    = "# END_AWS_SSO_CLI"
	FILE_TEMPLATE    = "%s\n%s\n%s\n"
)

type FileEdit struct {
	Prefix    string
	Suffix    string
	Template  *template.Template
	InputVars interface{}
}

var prompt = askUser

// GenerateSource returns the byte array of a template
func GenerateSource(fileTemplate string, vars interface{}) ([]byte, error) {
	templ, err := template.New("template").Parse(fileTemplate)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	err = templ.Execute(&buf, vars)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// NewFileEdit creates a new FileEdit object
func NewFileEdit(fileTemplate, ssoName string, vars interface{}) (*FileEdit, error) {
	var t string
	prefix := CONFIG_PREFIX
	suffix := CONFIG_SUFFIX

	if ssoName != "" && ssoName != DEFAULT_SSO_NAME {
		prefix = fmt.Sprintf("%s_%s", CONFIG_PREFIX, ssoName)
		suffix = fmt.Sprintf("%s_%s", CONFIG_SUFFIX, ssoName)
	}

	if fileTemplate != "" {
		t = fmt.Sprintf(FILE_TEMPLATE, prefix, fileTemplate, suffix)
	}
	templ, err := template.New("template").Parse(t)
	if err != nil {
		return &FileEdit{}, err
	}

	return &FileEdit{
		Prefix:    prefix,
		Suffix:    suffix,
		Template:  templ,
		InputVars: vars,
	}, nil
}

var diffWriter io.Writer = os.Stdout

// UpdateConfig does all the heavy lifting of updating (or creating) the file
// and optionally providing a diff for user to approve/view.  Returns true if
// changes were made (and the diff), false if no changes were made, or an error if something happened
func (f *FileEdit) UpdateConfig(printDiff, force bool, configFile string) (bool, string, error) {
	inputBytes, err := os.ReadFile(configFile)
	if err != nil {
		inputBytes = []byte{}
	}

	outputBytes, err := f.GenerateNewFile(configFile)
	if err != nil {
		return false, "", err
	}
	if len(outputBytes) == 0 {
		return false, "", fmt.Errorf("no data generated")
	}

	newFile := fmt.Sprintf("%s.new", configFile)

	diff := DiffBytes(inputBytes, outputBytes, configFile, GetHomePath(newFile))

	if len(diff) == 0 {
		// do nothing if there is no diff
		log.Infof("no changes made to %s", configFile)
		return false, "", nil
	}

	if !force {
		approved, err := prompt(configFile, diff)
		if err != nil {
			return false, diff, err
		}
		if !approved {
			return false, diff, nil
		}
	} else if printDiff {
		fmt.Fprintf(diffWriter, "%s", diff)
	}

	return true, diff, os.WriteFile(configFile, outputBytes, 0600)
}

// GenerateNewFile generates the contents of a new config file
func (f *FileEdit) GenerateNewFile(configFile string) ([]byte, error) {
	var output bytes.Buffer
	_ = io.Writer(&output)

	// read & write up to the prefix
	input, err := os.Open(configFile)
	if err != nil {
		if err = EnsureDirExists(configFile); err != nil {
			return []byte{}, err
		}

		input, err = os.Create(configFile)
		if err != nil {
			return []byte{}, err
		}
	}
	defer input.Close()
	r := bufio.NewReader(input)

	line, err := r.ReadString('\n')
	for err == nil && line != fmt.Sprintf("%s\n", f.Prefix) {
		if _, err = output.WriteString(line); err != nil {
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
	if err = f.Template.Execute(&output, f.InputVars); err != nil {
		return []byte{}, err
	}

	if !endOfFile {
		line, err = r.ReadString('\n')
		// consume our entries and the suffix
		for err == nil && line != fmt.Sprintf("%s\n", f.Suffix) {
			line, err = r.ReadString('\n')
		}

		// if not EOF or other error, read & write the config until EOF
		if err == nil {
			// read until error
			line, err = r.ReadString('\n')
			for err == nil {
				if _, err = output.WriteString(line); err != nil {
					return []byte{}, err
				}
				line, err = r.ReadString('\n')
			}
			if err != io.EOF {
				return []byte{}, err
			}
		}
	}
	// output.Flush()

	return output.Bytes(), nil
}

// askUser prompts the user to see if we should apply the diff
func askUser(configFile, diff string) (bool, error) {
	fmt.Printf("The following changes are proposed to %s:\n%s\n\n",
		GetHomePath(configFile), diff)
	label := fmt.Sprintf("Modify %s with proposed changes?", configFile)
	sel := promptui.Select{
		Label:        label,
		Items:        []string{"No", "Yes"},
		HideSelected: false,
		Stdout:       &BellSkipper{},
		Templates: &promptui.SelectTemplates{
			Selected: fmt.Sprintf(`%s: {{ . | faint }}`, label),
		},
	}

	_, val, err := sel.Run()
	return val == "Yes", err
}

// DiffBytes generates a diff between two byte arrays
func DiffBytes(aBytes, bBytes []byte, aName, bName string) string {
	edits := myers.ComputeEdits(span.URIFromPath(aName), string(aBytes), string(bBytes))
	diff := gotextdiff.ToUnified(aName, bName, string(aBytes), edits)
	return fmt.Sprintf("%s", diff)
}

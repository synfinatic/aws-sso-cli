package utils

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
	CONFIG_PREFIX = "# BEGIN_AWS_SSO_CLI"
	CONFIG_SUFFIX = "# END_AWS_SSO_CLI"
	FILE_TEMPLATE = "%s\n%s\n%s\n"
)

type FileEdit struct {
	Prefix    string
	Suffix    string
	Template  *template.Template
	InputVars interface{}
}

var prompt = askUser

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

func NewFileEdit(fileTemplate string, vars interface{}) (*FileEdit, error) {
	var t string

	if fileTemplate != "" {
		t = fmt.Sprintf(FILE_TEMPLATE, CONFIG_PREFIX, fileTemplate, CONFIG_SUFFIX)
	}
	templ, err := template.New("template").Parse(t)
	if err != nil {
		return &FileEdit{}, err
	}

	return &FileEdit{
		Prefix:    CONFIG_PREFIX,
		Suffix:    CONFIG_SUFFIX,
		Template:  templ,
		InputVars: vars,
	}, nil
}

var diffWriter io.Writer = os.Stdout

// UpdateConfig does all the heavy lifting of updating (or creating) the file
// and optionally providing a diff for user to approve/view
func (f *FileEdit) UpdateConfig(printDiff, force bool, configFile string) error {
	inputBytes, err := os.ReadFile(configFile)
	if err != nil {
		inputBytes = []byte{}
	}

	outputBytes, err := f.GenerateNewFile(configFile)
	if err != nil {
		return err
	}

	newFile := fmt.Sprintf("%s.new", configFile)

	diff := DiffBytes(inputBytes, outputBytes, configFile, GetHomePath(newFile))

	if len(diff) == 0 {
		// do nothing if there is no diff
		log.Infof("no changes made to %s", configFile)
		return nil
	}

	if !force {
		approved, err := prompt(configFile, diff)
		if err != nil {
			return err
		}
		if !approved {
			return nil
		}
	} else if printDiff {
		fmt.Fprintf(diffWriter, "%s", diff)
	}

	return os.WriteFile(configFile, outputBytes, 0600)
}

// GenerateNewFile generates the contents of a new config file
func (f *FileEdit) GenerateNewFile(configFile string) ([]byte, error) {
	var output bytes.Buffer
	var r *bufio.Reader
	w := bufio.NewWriter(&output)

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
	r = bufio.NewReader(input)

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
	if err = f.Template.Execute(w, f.InputVars); err != nil {
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

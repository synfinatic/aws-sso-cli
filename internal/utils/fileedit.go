package utils

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
)

const (
	CONFIG_PREFIX = "# BEGIN_AWS_SSO_CLI"
	CONFIG_SUFFIX = "# END_AWS_SSO_CLI"
)

type FileEdit struct {
	Prefix    string
	Suffix    string
	Template  *template.Template
	InputVars interface{}
}

func NewFileEdit(templ *template.Template, vars interface{}) *FileEdit {
	return &FileEdit{
		Prefix:    CONFIG_PREFIX,
		Suffix:    CONFIG_SUFFIX,
		Template:  templ,
		InputVars: vars,
	}
}

// updateConfig calculates the diff
func (f *FileEdit) UpdateConfig(printDiff, force bool, oldFile string) error {
	// open our config file
	inputBytes, err := os.ReadFile(oldFile)
	if err != nil {
		return err
	}

	outputBytes, err := f.GenerateNewFile(oldFile)
	if err != nil {
		return err
	}

	newFile := fmt.Sprintf("%s.new", oldFile)

	diff, err := DiffBytes(inputBytes, outputBytes, oldFile, GetHomePath(newFile))
	if err != nil {
		return err
	}

	if len(diff) == 0 {
		// do nothing if there is no diff
		log.Infof("No changes to made to %s", oldFile)
		return nil
	}

	if printDiff {
		fmt.Printf("%s", diff)
		return nil
	}

	if !force {
		fmt.Printf("The following changes are proposed to %s:\n%s\n\n",
			GetHomePath(oldFile), diff)
		label := "Modify config file with proposed changes?"
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
		if err != nil {
			return err
		}

		if val != "Yes" {
			fmt.Printf("Aborting.")
			return nil
		}
	}

	return os.WriteFile(oldFile, outputBytes, 0600)
}

// GenerateNewFile generates the contents of a new config file
func (f *FileEdit) GenerateNewFile(configFile string) ([]byte, error) {
	var output bytes.Buffer
	w := bufio.NewWriter(&output)

	// read & write up to the prefix
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

// DiffBytes generates a diff between two byte arrays
func DiffBytes(aBytes, bBytes []byte, aName, bName string) (string, error) {
	edits := myers.ComputeEdits(span.URIFromPath(aName), string(aBytes), string(bBytes))
	diff := gotextdiff.ToUnified(aName, bName, string(aBytes), edits)
	log.Debugf("diff:\n%v", diff)
	return fmt.Sprintf("%s", diff), nil
}

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
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"text/template"

	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

const BASH_PROFILE = `# BEGIN_AWS_SSO_CLI

complete -C {{ .Executable }} aws-sso

_aws_sso_profile_complete(){
    local words
    for i in $(aws-sso -L error list Profile | tail +5 | sed -Ee 's|:|\\\\:|g') ; do
        words="${words} ${i}"
    done
    COMPREPLY=($(compgen -W "${words}" "${COMP_WORDS[1]}"))
}

alias aws-sso-profile='source {{ .HelperScript }}'
alias aws-sso-clear='eval $(aws-sso -L error eval -c)'

# END_AWS_SSO_CLI
`

const BASH_HELPER_FILE = "helper-aws-sso-profile"
const BASH_HELPER = `#!/usr/bin/env bash
eval $({{ .Executable }} -L error eval $AWS_SSO_HELPER_ARGS -p $1 $2 $3 $4 $5 $6 $7)
`

func writeBashFiles() error {
	var err error
	var exec, helper string
	var output bytes.Buffer

	if exec, err = os.Executable(); err != nil {
		return fmt.Errorf("unable to determine our own executable: %s", err.Error())
	}

	exec, err = filepath.Abs(exec)
	if err != nil {
		return fmt.Errorf("unable to determine absolute path: %s", err.Error())
	}

	helper = filepath.Join(filepath.Dir(exec), BASH_HELPER_FILE)

	args := map[string]string{
		"Executable":   exec,
		"HelperScript": helper,
	}

	templ, err := template.New("bash_profile").Parse(BASH_PROFILE)
	if err != nil {
		log.Panicf("Unable to parse bash_profile template: %s", err.Error())
	}

	f := utils.NewFileEdit(templ, args)
	path := utils.GetHomePath("~/.bash_profile")

	if err = f.UpdateConfig(true, false, path); err != nil {
		return err
	}

	fh, err := os.OpenFile(helper, os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		log.Panicf("Unable to create %s: %s", path, err.Error())
	}

	templ, err = template.New("helper").Parse(BASH_HELPER)
	if err != nil {
		log.Panicf("Unable to parse helper template: %s", err.Error())
	}

	w := bufio.NewWriter(&output)
	err = templ.Execute(w, args)

	if _, err = fh.Write(output.Bytes()); err != nil {
		return err
	}
	fh.Close()
	return nil
}

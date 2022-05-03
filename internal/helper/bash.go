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
	"os"
	"path/filepath"

	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

const BASH_PROFILE = `# BEGIN_AWS_SSO_CLI

_aws_sso_profile_complete(){
    local words
    for i in $({{ .Executable }} -L error list Profile | tail -n +5 | sed -Ee 's|:|\\\\:|g') ; do
        words="${words} ${i}"
    done
    COMPREPLY=($(compgen -W "${words}" "${COMP_WORDS[1]}"))
}

alias aws-sso-profile='source {{ .HelperScript }}'
alias aws-sso-clear='eval $(aws-sso -L error eval -c)'

complete -F _aws_sso_profile_complete aws-sso-profile
complete -C {{ .Executable }} aws-sso

# END_AWS_SSO_CLI
`

const BASH_HELPER_FILE = "helper-aws-sso-profile"
const BASH_HELPER = `# BEGIN_AWS_SSO_CLI
eval $({{ .Executable }} -L error eval $AWS_SSO_HELPER_ARGS -p $1 $2 $3 $4 $5 $6 $7)
# END_AWS_SSO_CLI
`

func helperPath() string {
	var exec string
	var err error

	if exec, err = os.Executable(); err != nil {
		log.Panicf("unable to determine our own executable: %s", err.Error())
	}

	exec, err = filepath.Abs(exec)
	if err != nil {
		log.Panicf("unable to determine absolute path: %s", err.Error())
	}

	return filepath.Join(filepath.Dir(exec), BASH_HELPER_FILE)

}

func writeBashFiles() error {
	var err error
	var exec, helper string

	helper = helperPath()
	exec, _ = os.Executable()

	args := map[string]string{
		"Executable":   exec,
		"HelperScript": helper,
	}

	// write ~/bash_profile
	f, err := utils.NewFileEdit(BASH_PROFILE, args)
	if err != nil {
		return err
	}

	path := utils.GetHomePath("~/.bash_profile")

	if err = f.UpdateConfig(false, false, path); err != nil {
		return err
	}

	// Now do the helper file
	f, err = utils.NewFileEdit(BASH_HELPER, args)
	if err != nil {
		return err
	}

	if err = f.UpdateConfig(false, true, helper); err != nil {
		return err
	}

	log.Infof("wrote %s", helper)
	return nil
}

func uninstallBashFiles() error {
	helper := helperPath()
	err := os.Remove(helper)
	if err != nil {
		log.Warnf("unable to delete: %s", err.Error())
	}

	fe, err := utils.NewFileEdit("", "")
	if err != nil {
		return nil
	}

	path := utils.GetHomePath("~/.bash_profile")
	err = fe.StripConfig(false, false, path)
	if err != nil {
		log.Warnf("unable to remove config: %s", err.Error())
	}

	return nil
}

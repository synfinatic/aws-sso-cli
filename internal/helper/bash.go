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

	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

const BASH_PROFILE = `# BEGIN_AWS_SSO_CLI

_aws_sso_profile_complete(){
  local words
  for i in $({{ .Executable }} -L error list --profiles) ; do 
    if [ -n "$1" ]; then
      words="${words} ${i}"
    fi
  done
  COMPREPLY=($(compgen -W "${words}" "${COMP_WORDS[1]}"))
}

aws-sso-profile(){
  if [ -n "$AWS_PROFILE" ]; then
     echo "Unable to assume a role while AWS_PROFILE is set"
     return 1
  fi
  eval $({{ .Executable }} -L error eval -p "$1" $AWS_SSO_HELPER_ARGS)
  if [ "$AWS_SSO_PROFILE" != "$1" ]; then
    return 1
  fi
}

aws-sso-clear(){
  if [ -z "$AWS_SSO_PROFILE" ]; then
    echo "AWS_SSO_PROFILE is not set"
	return 1
  fi
  eval $(aws-sso -L error eval -c)
}

complete -F _aws_sso_profile_complete aws-sso-profile
complete -C {{ .Executable }} aws-sso

# END_AWS_SSO_CLI
`

func writeBashFiles() error {
	var err error
	var exec string

	exec, _ = os.Executable()

	args := map[string]string{
		"Executable": exec,
	}

	// write ~/bash_profile
	fe, err := utils.NewFileEdit(BASH_PROFILE, args)
	if err != nil {
		return err
	}

	path := utils.GetHomePath("~/.bash_profile")

	if err = fe.UpdateConfig(false, false, path); err != nil {
		return err
	}

	return nil
}

func uninstallBashFiles() error {
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

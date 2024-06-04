package awsconfig

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
	"fmt"
	"io"
	"os"
	"text/template"
)

const (
	CREDENTIALS_TEMPLATE = `{{range $profile := . }}
[{{ $profile.Profile }}]
# Expires: {{ $profile.Expires }}
aws_access_key_id = {{ $profile.AccessKeyId }}
aws_secret_access_key = {{ $profile.SecretAccessKey }}
aws_session_token = {{ $profile.SessionToken }}
{{end}}
`
)

type ProfileCredentials struct {
	Profile         string
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expires         string
}

func genProfileCredentials(output io.Writer, creds []ProfileCredentials) error {
	if len(creds) == 0 {
		return fmt.Errorf("no credentials to write")
	}
	t := template.Must(template.New("template").Parse(CREDENTIALS_TEMPLATE))
	return t.Execute(output, creds)
}

// AwsCredentialsFile generates a new AWS credentials file or writes to STDOUT
// cfile is the path to the file to write to, or "" to write to stdout
// flags is the flags to pass to os.OpenFile
// creds is the list of credentials to write
func WriteProfileCredentials(cfile string, flags int, creds []ProfileCredentials) error {
	var ofile *os.File
	var err error

	ofile, err = os.OpenFile(cfile, flags, 0600)
	if err != nil {
		return err
	}
	defer ofile.Close()

	return genProfileCredentials(ofile, creds)
}

func PrintProfileCredentials(creds []ProfileCredentials) error {
	return genProfileCredentials(os.Stdout, creds)
}

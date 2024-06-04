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
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/MakeNowJust/heredoc"

	"github.com/stretchr/testify/assert"
)

func TestGenProfileCredentials(t *testing.T) {
	// Create a buffer to capture STDOUT
	buf := &bytes.Buffer{}

	// Create example ProfileCredentials
	creds := []ProfileCredentials{
		{
			Profile:         "first",
			AccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			SessionToken:    "AQoDYXdzEJr...<remainder of security token>",
			Expires:         "2024-06-03 17:56:11 -0700 PDT",
		},
		{
			Profile:         "second",
			AccessKeyId:     "AKIAYOMAMMAEXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/YESMAN/bPxRfiCYEXAMPLEKEY",
			SessionToken:    "AQoEdBaglyJunior...<remainder of security token>",
			Expires:         "2024-06-03 18:58:01 -0700 PDT",
		},
	}

	err := genProfileCredentials(buf, creds)
	assert.NoError(t, err)

	credsResult := heredoc.Doc(`

		[first]
		# Expires: 2024-06-03 17:56:11 -0700 PDT
		aws_access_key_id = AKIAIOSFODNN7EXAMPLE
		aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
		aws_session_token = AQoDYXdzEJr...<remainder of security token>

		[second]
		# Expires: 2024-06-03 18:58:01 -0700 PDT
		aws_access_key_id = AKIAYOMAMMAEXAMPLE
		aws_secret_access_key = wJalrXUtnFEMI/YESMAN/bPxRfiCYEXAMPLEKEY
		aws_session_token = AQoEdBaglyJunior...<remainder of security token>

	`)

	assert.Equal(t, credsResult, buf.String())

	// replace os.Stdout with our buffer
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err = PrintProfileCredentials(creds)
	assert.NoError(t, err)
	w.Close()
	output, _ := io.ReadAll(r)
	assert.Equal(t, credsResult, string(output))

	// restore stdout
	os.Stdout = old
}

func TestGenProfileCredentialsErrors(t *testing.T) {
	// Test with an empty slice
	buf := &bytes.Buffer{}
	err := genProfileCredentials(buf, []ProfileCredentials{})
	assert.Error(t, err)
}

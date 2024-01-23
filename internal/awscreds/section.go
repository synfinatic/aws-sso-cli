package awscreds

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
	"gopkg.in/ini.v1"
)

func HasStaticCreds(s *ini.Section) bool {
	awsAccessKeyId := false
	awsSecretAccessKey := false
	for _, key := range s.KeyStrings() {
		switch key {
		case "aws_access_key_id":
			awsAccessKeyId = true
		case "aws_secret_access_key":
			awsSecretAccessKey = true
		case "mfa_serial":
			// we don't support prompting for MFA so don't import them
			log.Infof("Skipping MFA enabled profile: %s", s.Name())
			return false
		}
	}
	return awsAccessKeyId && awsSecretAccessKey
}

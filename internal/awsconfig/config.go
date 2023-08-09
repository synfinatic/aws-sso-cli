package awsconfig

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
	"fmt"
	//	"os"
	"strings"

	"github.com/synfinatic/aws-sso-cli/internal/storage"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
	"gopkg.in/ini.v1"
)

const (
	CONFIG_FILE      = "~/.aws/config"
	CREDENTIALS_FILE = "~/.aws/credentials" // #nosec
)

type AwsConfig struct {
	ConfigFile      string
	Config          *ini.File
	CredentialsFile string
	Credentials     *ini.File
	Profiles        map[string]map[string]interface{} // profile.go
}

// NewAwsConfig creates a new *AwsConfig struct
func NewAwsConfig(config, credentials string) (*AwsConfig, error) {
	var err error
	a := AwsConfig{}
	p := utils.GetHomePath(config)

	if a.Config, err = ini.Load(p); err != nil {
		return nil, fmt.Errorf("unable to open %s: %s", p, err.Error())
	} else {
		a.ConfigFile = config
	}

	p = utils.GetHomePath(credentials)
	if a.Credentials, err = ini.Load(p); err == nil {
		a.CredentialsFile = p
	}

	return &a, nil
}

// StaticProfiles returns a list of all the profiles with static API creds
// stored in ~/.aws/config and ~/.aws/credentials
func (a *AwsConfig) StaticProfiles() ([]Profile, error) {
	profiles := []Profile{}
	creds := a.Credentials

	for _, profile := range a.Config.Sections() {
		x := strings.Split(profile.Name(), " ")
		if x[0] != "profile" || len(x) != 2 {
			log.Errorf("invalid profile: %s", profile.Name())
			continue
		}

		if HasStaticCreds(profile) {
			log.Debugf("Found api keys for %s with in config file", x[1])
			profiles = append(profiles,
				Profile{
					Name:            x[1],
					AccessKeyId:     profile.Key("aws_access_key_id").String(),
					SecretAccessKey: profile.Key("aws_secret_access_key").String(),
					FromConfig:      true,
				})
		} else if creds != nil {
			if cp, err := creds.GetSection(x[1]); err == nil {
				if cp != nil && HasStaticCreds(cp) {
					log.Debugf("Found api keys for %s in credentials file", x[1])
					profiles = append(profiles,
						Profile{
							Name:            x[1],
							AccessKeyId:     cp.Key("aws_access_key_id").String(),
							SecretAccessKey: cp.Key("aws_secret_access_key").String(),
							FromConfig:      false,
						})
				}
			}
		} else {
			log.Errorf("skipping because no credentials file")
		}
	}
	return profiles, nil
}

// UpdateSecureStore writes any new role ARN credentials to the provided SecureStorage
func (a *AwsConfig) UpdateSecureStore(store storage.SecureStorage) error {
	profiles, err := a.StaticProfiles()
	if err != nil {
		return err
	}

	for _, p := range profiles {
		arn, err := p.GetArn()
		if err != nil {
			return err
		}
		accountid, username, _ := utils.ParseUserARN(arn)

		creds := storage.StaticCredentials{
			UserName:        username,
			AccountId:       accountid,
			AccessKeyId:     p.AccessKeyId,
			SecretAccessKey: p.SecretAccessKey,
		}
		if err = store.SaveStaticCredentials(arn, creds); err != nil {
			return err
		}
	}
	return nil
}

// Write updates the AWS ~/.aws/config file to use aws-sso via a credential_process
// and removes the associated ~/.aws/credentials entries
func (a *AwsConfig) Write() error {
	return nil
}

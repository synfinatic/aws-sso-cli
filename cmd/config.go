package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021 Aaron Turner  <synfinatic at gmail dot com>
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
	"strconv"
)

type AWSProfile struct {
	Alias     string `koanf:"Alias" yaml:"Alias,omitempty"`         // Friendly name
	Role      string `koanf:"Role" yaml:"Role,omitempty"`           // AWS Role Name
	Region    string `koanf:"Region" yaml:"Region,omitempty"`       // AWS Default Region
	AccountId string `koanf:"AccountId" yaml:"AccountId,omitempty"` // AWS AccountId
}

type ConfigFile struct {
	SSO          map[string]*SSOConfig `koanf:"SSOConfig" yaml:"SSOConfig,omitempty"`
	DefaultSSO   string                `koanf:"DefaultSSO" yaml:"DefaultSSO,omitempty"`   // specify default SSO by key
	SecureStore  string                `koanf:"SecureStore" yaml:"SecureStore,omitempty"` // json or keyring
	JsonStore    JsonStoreConfig       `koanf:"Json" yaml:"Json,omitempty"`
	KeyringStore KeyringStoreConfig    `koanf:"Keyring" yaml:"Keyring,omitempty"`
}

type SSOConfig struct {
	SSORegion string                `koanf:"SSORegion" yaml:"SSORegion"`
	Region    string                `koanf:"Region" yaml:"Region"`
	StartUrl  string                `koanf:"StartUrl" yaml:"StartUrl"`
	Accounts  map[int64]*SSOAccount `koanf:"Accounts" yaml:"Accounts,omitempty"`
}

type SSOAccount struct {
	Name  string            `koanf:"Name" yaml:"Name,omitempty"` // Admin configured Account Name
	Tags  map[string]string `koanf:"Tags" yaml:"Tags,omitempty" `
	Roles []*SSORole        `koanf:"Roles" yaml:"Roles,omitempty"`
}

type SSORole struct {
	ARN  string            `koanf:"ARN" yaml:"ARN"`
	Tags map[string]string `koanf:"Tags" yaml:"Tags,omitempty"`
}

type JsonStoreConfig struct {
	File string `koanf:"File" yaml:"File"` // Filename
}

type KeyringStoreConfig struct {
	// ???
}

func (a *SSOAccount) HasRole(arn string) bool {
	hasRole := false
	for _, role := range a.Roles {
		if role.ARN == arn {
			hasRole = true
			break
		}
	}
	return hasRole
}

func (s *SSOConfig) UpdateRoles(roles map[string][]RoleInfo) (int64, error) {
	var changes int64 = 0
	for account, accountInfo := range roles {
		accountId, err := strconv.ParseInt(account, 10, 64)
		if err != nil {
			return 0, err
		}
		if s.Accounts == nil {
			s.Accounts = map[int64]*SSOAccount{}
		}
		_, hasAccount := s.Accounts[accountId]
		if !hasAccount {
			s.Accounts[accountId] = &SSOAccount{
				Roles: []*SSORole{},
			}
		}

		for _, roleInfo := range accountInfo {
			if !hasAccount || !s.Accounts[accountId].HasRole(roleInfo.RoleArn()) {
				changes += 1
				s.Accounts[accountId].Roles = append(s.Accounts[accountId].Roles, &SSORole{
					ARN: roleInfo.RoleArn(),
				})
			}
		}
	}
	return changes, nil
}

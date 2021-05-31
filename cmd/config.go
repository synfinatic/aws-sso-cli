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

type AWSProfile struct {
	Alias     string `koanf:"Alias"`     // Friendly name
	Role      string `koanf:"Role"`      // AWS Role Name
	Region    string `koanf:"Region"`    // AWS Default Region
	AccountId string `koanf:"AccountId"` // AWS AccountId
}

type ConfigFile struct {
	SSO          map[string]*SSOConfig `koanf:"SSOConfig"`
	DefaultSSO   string                `koanf:"DefaultSSO"`  // specify default SSO by key
	SecureStore  string                `koanf:"SecureStore"` // json or keyring
	JsonStore    JsonStoreConfig       `koanf:"JsonStore"`
	KeyringStore KeyringStoreConfig    `koanf:"KeyringStore"`
}

type SSOConfig struct {
	SSORegion string                `koanf:"SSORegion"`
	StartUrl  string                `koanf:"StartUrl"`
	Accounts  map[int64]*SSOAccount `koanf:"Accounts"`
}

type SSOAccount struct {
	Name  string            `koanf:"Name"` // Admin configured Account Name
	Tags  map[string]string `koanf:"Tags"`
	Roles []*SSORole        `koanf:"Roles"`
}

type SSORole struct {
	ARN  string            `koanf:"ARN"`
	Tags map[string]string `koanf:"Tags"`
}

type JsonStoreConfig struct {
	File string `koanf:"File"` // Filename
}

type KeyringStoreConfig struct {
	// ???
}

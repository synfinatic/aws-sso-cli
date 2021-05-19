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
	Alias     string `koanf:"alias"`      // Friendly name
	Role      string `koanf:"role"`       // AWS Role Name
	Region    string `koanf:"region"`     // AWS Default Region
	AccountId string `koanf:"account_id"` // AWS AccountId
}

type SSOConfig struct {
	Region      string `koanf:"region"`
	SSORegion   string `koanf:"sso_region"`
	StartUrl    string `koanf:"start_url"`
	SecureStore string `koanf:"secure_store"`
	JsonStore   struct {
		File string `koanf:"file"`
		// ??
	} `koanf:"json_store"`
	KeyringStore struct {
		// ???
	} `koanf:"keyring_store"`
	Profiles *[]AWSProfile `koanf:"profiles"`
}

package storage

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

// Define the interface for storing our AWS SSO data
type SecureStorage interface {
	SaveRegisterClientData(string, RegisterClientData) error
	GetRegisterClientData(string, *RegisterClientData) error
	DeleteRegisterClientData(string) error

	SaveCreateTokenResponse(string, CreateTokenResponse) error
	GetCreateTokenResponse(string, *CreateTokenResponse) error
	DeleteCreateTokenResponse(string) error

	// Temporary STS creds
	SaveRoleCredentials(string, RoleCredentials) error
	GetRoleCredentials(string, *RoleCredentials) error
	DeleteRoleCredentials(string) error

	// Static API creds
	SaveStaticCredentials(string, StaticCredentials) error
	GetStaticCredentials(string, *StaticCredentials) error
	DeleteStaticCredentials(string) error
	ListStaticCredentials() []string

	// ECS Server Bearer Token
	SaveEcsBearerToken(string) error
	GetEcsBearerToken() (string, error)
	DeleteEcsBearerToken() error

	// ECS Server SSL Cert
	SaveEcsSslKeyPair([]byte, []byte) error
	DeleteEcsSslKeyPair() error
	GetEcsSslCert() (string, error)
	GetEcsSslKey() (string, error)
}

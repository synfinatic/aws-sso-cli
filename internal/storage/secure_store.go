package storage

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2026 Aaron Turner  <synfinatic at gmail dot com>
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

import "context"

// Define the interface for storing our AWS SSO data.
// Save* and Delete* methods accept a context for cancellation and timeout
// during file-lock acquisition. Get* methods read from an in-memory cache
// and do not need a context.
type SecureStorage interface {
	SaveRegisterClientData(ctx context.Context, region string, client RegisterClientData) error
	GetRegisterClientData(region string, client *RegisterClientData) error
	DeleteRegisterClientData(ctx context.Context, region string) error

	SaveCreateTokenResponse(ctx context.Context, key string, token CreateTokenResponse) error
	GetCreateTokenResponse(key string, token *CreateTokenResponse) error
	DeleteCreateTokenResponse(ctx context.Context, key string) error

	// Temporary STS creds
	SaveRoleCredentials(ctx context.Context, arn string, token RoleCredentials) error
	GetRoleCredentials(arn string, token *RoleCredentials) error
	DeleteRoleCredentials(ctx context.Context, arn string) error

	// Static API creds
	SaveStaticCredentials(ctx context.Context, arn string, creds StaticCredentials) error
	GetStaticCredentials(arn string, creds *StaticCredentials) error
	DeleteStaticCredentials(ctx context.Context, arn string) error
	ListStaticCredentials() []string

	// ECS Server Bearer Token
	SaveEcsBearerToken(ctx context.Context, token string) error
	GetEcsBearerToken() (string, error)
	DeleteEcsBearerToken(ctx context.Context) error

	// ECS Server SSL Cert
	SaveEcsSslKeyPair(ctx context.Context, privateKey []byte, certChain []byte) error
	DeleteEcsSslKeyPair(ctx context.Context) error
	GetEcsSslCert() (string, error)
	GetEcsSslKey() (string, error)
}

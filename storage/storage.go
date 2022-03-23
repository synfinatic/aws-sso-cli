package storage

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
	"time"

	"github.com/synfinatic/aws-sso-cli/utils"
)

// this struct should be cached for long term if possible
type RegisterClientData struct {
	AuthorizationEndpoint string `json:"authorizationEndpoint,omitempty"`
	ClientId              string `json:"clientId"`
	ClientIdIssuedAt      int64  `json:"clientIdIssuedAt"`
	ClientSecret          string `json:"clientSecret"`
	ClientSecretExpiresAt int64  `json:"clientSecretExpiresAt"`
	TokenEndpoint         string `json:"tokenEndpoint,omitempty"`
}

// Expired returns true if it has expired or will in the next hour
func (r *RegisterClientData) Expired() bool {
	// XXX: I think an hour buffer here is fine?
	return r.ClientSecretExpiresAt <= time.Now().Add(time.Hour).Unix()
}

type StartDeviceAuthData struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationUri         string `json:"verificationUri"`
	VerificationUriComplete string `json:"verificationUriComplete"`
	ExpiresIn               int32  `json:"expiresIn"`
	Interval                int32  `json:"interval"`
}

type CreateTokenResponse struct {
	AccessToken  string `json:"accessToken"` // should be cached to issue new creds
	ExpiresIn    int32  `json:"expiresIn"`   // number of seconds it expires in (from AWS)
	ExpiresAt    int64  `json:"expiresAt"`   // Unix time when it expires
	IdToken      string `json:"IdToken"`
	RefreshToken string `json:"RefreshToken"`
	TokenType    string `json:"tokenType"`
}

// Expired returns true if it has expired or will in the next minute
func (t *CreateTokenResponse) Expired() bool {
	// XXX: I think an minute buffer here is fine?
	return t.ExpiresAt <= time.Now().Add(time.Minute).Unix()
}

type RoleCredentials struct { // Cache
	RoleName        string `json:"roleName"`
	AccountId       int64  `json:"accountId"`
	AccessKeyId     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken"`
	Expiration      int64  `json:"expiration"` // not in seconds, but millisec
}

// RoleArn returns the ARN for the role
func (r *RoleCredentials) RoleArn() string {
	return utils.MakeRoleARN(r.AccountId, r.RoleName)
}

// ExpireEpoch return seconds since unix epoch when we expire
func (r *RoleCredentials) ExpireEpoch() int64 {
	return time.UnixMilli(r.Expiration).Unix() // yes, millisec
}

// ExpireString returns the time the creds expire in the format of "2006-01-02 15:04:05.999999999 -0700 MST"
func (r *RoleCredentials) ExpireString() string {
	return time.UnixMilli(r.Expiration).String() // yes, millisec
}

// Expired returns if these role creds have expired or will expire in the next minute
func (r *RoleCredentials) Expired() bool {
	now := time.Now().Add(time.Minute).UnixMilli() // yes, millisec
	return r.Expiration <= now
}

// Return expire time in ISO8601 / RFC3339 format
func (r *RoleCredentials) ExpireISO8601() string {
	return time.Unix(r.ExpireEpoch(), 0).Format(time.RFC3339)
}

// AccountIdStr returns our AccountId as a string
func (r *RoleCredentials) AccountIdStr() string {
	s, err := utils.AccountIdToString(r.AccountId)
	if err != nil {
		log.WithError(err).Fatalf("Unable to parse accountId from AWS role credentials")
	}
	return s
}

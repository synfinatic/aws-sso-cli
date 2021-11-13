package storage

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
	"fmt"
	"strconv"
	"time"
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

func (r *RegisterClientData) Expired() bool {
	// XXX: I think an hour buffer here is fine?
	return r.ClientSecretExpiresAt <= time.Now().Add(time.Hour).Unix()
}

type StartDeviceAuthData struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationUri         string `json:"verificationUri"`
	VerificationUriComplete string `json:"verificationUriComplete"`
	ExpiresIn               int64  `json:"expiresIn"`
	Interval                int64  `json:"interval"`
}

type CreateTokenResponse struct {
	AccessToken  string `json:"accessToken"` // should be cached to issue new creds
	ExpiresIn    int64  `json:"expiresIn"`   // number of seconds it expires in (from AWS)
	ExpiresAt    int64  `json:"expiresAt"`   // Unix time when it expires
	IdToken      string `json:"IdToken"`
	RefreshToken string `json:"RefreshToken"`
	TokenType    string `json:"tokenType"`
}

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
	Expiration      int64  `json:"expiration"` // not in seconds!
}

func (r *RoleCredentials) RoleArn() string {
	return fmt.Sprintf("arn:aws:iam:%d:role/%s", r.AccountId, r.RoleName)
}

// Return seconds since unix epoch when we expire
func (r *RoleCredentials) ExpireEpoch() int64 {
	return r.Expiration / 1000
}

func (r *RoleCredentials) ExpireString() string {
	// apparently Expiration is in ms???
	return time.Unix(r.Expiration/1000, 0).String()
}

func (r *RoleCredentials) IsExpired() bool {
	now := time.Now().Add(time.Minute).Unix()
	return r.Expiration/1000 <= now
}

// AccountIdStr returns our AccountId as a string
func (r *RoleCredentials) AccountIdStr() string {
	return strconv.FormatInt(r.AccountId, 10)
}

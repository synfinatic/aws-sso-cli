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

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"reflect"
	"time"

	"github.com/synfinatic/aws-sso-cli/internal/awsparse"
	"github.com/synfinatic/aws-sso-cli/internal/logger"
	"github.com/synfinatic/flexlog"
	"github.com/synfinatic/gotable"
)

var log flexlog.FlexLogger

func init() {
	log = logger.GetLogger()
}

type GrantType string

const (
	GrantTypeDeviceCode        GrantType = "urn:ietf:params:oauth:grant-type:device_code"
	GrantTypeAuthorizationCode GrantType = "authorization_code" // aka PKCE
	GrantTypeRefreshToken      GrantType = "refresh_token"
)

// this struct should be cached for long term if possible
type RegisterClientData struct {
	AuthorizationEndpoint string      `json:"authorizationEndpoint,omitempty"`
	ClientId              string      `json:"clientId"`
	ClientIdIssuedAt      int64       `json:"clientIdIssuedAt"`
	ClientSecret          string      `json:"clientSecret"` // nolint:gosec
	ClientSecretExpiresAt int64       `json:"clientSecretExpiresAt"`
	TokenEndpoint         string      `json:"tokenEndpoint,omitempty"`
	GrantTypes            []GrantType `json:"grantTypes,omitempty"`
}

// UnmarshalJSON implements json.Unmarshaler. If GrantTypes is absent or empty
// in stored JSON (written by older versions of aws-sso-cli), it defaults to
// ["device_code"] — which does NOT include "authorization_code", so stale
// registrations will trigger a transparent one-time re-auth.
func (r *RegisterClientData) UnmarshalJSON(b []byte) error {
	type plain RegisterClientData // break recursion
	var tmp plain
	if err := json.Unmarshal(b, &tmp); err != nil {
		return err
	}
	*r = RegisterClientData(tmp)
	if len(r.GrantTypes) == 0 {
		r.GrantTypes = []GrantType{GrantTypeDeviceCode}
	}
	return nil
}

func (r *RegisterClientData) SupportsGrantType(gt GrantType) bool {
	if len(r.GrantTypes) > 2 {
		// Hack to deal with v2.2.0/2.2.1 bug where we supported all 3 grant types
		// but some AWS SSO configs did not like authorization_code + device_code together
		// see: https://github.com/synfinatic/aws-sso-cli/issues/1359
		return false
	}
	for _, g := range r.GrantTypes {
		if g == gt {
			return true
		}
	}
	return false
}

// SupportsAuthorizationCode returns true if the registration includes the
// "authorization_code" grant type.
func (r *RegisterClientData) SupportsAuthorizationCode() bool {
	return r.SupportsGrantType(GrantTypeAuthorizationCode)
}

// SupportsRefreshToken returns true if the registration includes the
// "refresh_token" grant type.
func (r *RegisterClientData) SupportsRefreshToken() bool {
	return r.SupportsGrantType(GrantTypeRefreshToken)
}

// SupportsDeviceCode returns true if the registration includes the
// "device_code" grant type.
func (r *RegisterClientData) SupportsDeviceCode() bool {
	return r.SupportsGrantType(GrantTypeDeviceCode)
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
	// should be cached to issue new creds
	AccessToken  string `json:"accessToken"`  // nolint:gosec
	ExpiresIn    int32  `json:"expiresIn"`    // number of seconds it expires in (from AWS)
	ExpiresAt    int64  `json:"expiresAt"`    // Unix time when it expires
	IdToken      string `json:"IdToken"`      // not implemented by AWS
	RefreshToken string `json:"RefreshToken"` // nolint:gosec
	TokenType    string `json:"tokenType"`    // should be "Bearer"
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
	SessionToken    string `json:"sessionToken"` // nolint:gosec
	Expiration      int64  `json:"expiration"`   // not in seconds, but millisec
	RoleChaining    bool   `json:"roleChaining"` // true if we used AssumeRole to get these creds
}

// RoleArn returns the ARN for the role
func (r *RoleCredentials) RoleArn() string {
	return awsparse.MakeRoleARN(r.AccountId, r.RoleName)
}

// ExpireEpoch return seconds since unix epoch when we expire
func (r *RoleCredentials) ExpireEpoch() int64 {
	return time.UnixMilli(r.Expiration).Unix() // yes, millisec
}

// Expired returns if these role creds have expired or will expire in the next minute
func (r *RoleCredentials) Expired() bool {
	now := time.Now().Add(time.Minute).UnixMilli() // yes, millisec
	return r.Expiration <= now
}

// Return expire time in ISO8601 / RFC3339 format
func (r *RoleCredentials) ExpireString() string {
	return time.Unix(r.ExpireEpoch(), 0).Format(time.RFC3339)
}

// AccountIdStr returns our AccountId as a string
func (r *RoleCredentials) AccountIdStr() string {
	s, err := awsparse.AccountIdToString(r.AccountId)
	if err != nil {
		log.Fatal("unable to parse accountId from AWS role credentials", "error", err.Error())
	}
	return s
}

// Validate ensures we have the necessary fields
func (r *RoleCredentials) Validate() error {
	if r.RoleName == "" {
		return fmt.Errorf("%s", "missing roleName")
	}

	if r.AccessKeyId == "" {
		return fmt.Errorf("%s", "missing accessKeyId")
	}

	if r.SecretAccessKey == "" {
		return fmt.Errorf("%s", "missing secretAccessKey")
	}

	if r.AccountId == 0 {
		return fmt.Errorf("%s", "missing accountId")
	}

	if r.SessionToken == "" {
		return fmt.Errorf("%s", "missing sessionToken")
	}

	if r.Expiration == 0 {
		return fmt.Errorf("%s", "missing expiration")
	}
	return nil
}

type StaticCredentials struct { // Cache and storage
	Profile         string            `json:"Profile" header:"Profile"`
	UserName        string            `json:"userName" header:"UserName"`
	AccountId       int64             `json:"accountId" header:"AccountId"`
	AccessKeyId     string            `json:"accessKeyId"`
	SecretAccessKey string            `json:"secretAccessKey"`
	Tags            map[string]string `json:"Tags" header:"Tags"`
}

// GetHeader is required for GenerateTable()
func (sc StaticCredentials) GetHeader(fieldName string) (string, error) {
	v := reflect.ValueOf(sc)
	return gotable.GetHeaderTag(v, fieldName)
}

// RoleArn returns the ARN for the role
func (sc *StaticCredentials) UserArn() string {
	return awsparse.MakeUserARN(sc.AccountId, sc.UserName)
}

// AccountIdStr returns our AccountId as a string
func (sc *StaticCredentials) AccountIdStr() string {
	s, err := awsparse.AccountIdToString(sc.AccountId)
	if err != nil {
		log.Fatal("Invalid AccountId from AWS static credentials", "accountId", sc.AccountId)
	}
	return s
}

// ValidateSSLCertificate ensures we have a valid SSL certificate
func ValidateSSLCertificate(certChain []byte) error {
	block, _ := pem.Decode(certChain)

	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return fmt.Errorf("certificate chain file is not a valid certificate: %w", err)
	}
	return nil
}

// ValidateSSLPrivateKey ensures we have a valid SSL private key
func ValidateSSLPrivateKey(privateKey []byte) error {
	// if we have no private key, then we're good
	if len(privateKey) == 0 {
		return nil
	}
	block, _ := pem.Decode(privateKey)

	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		return fmt.Errorf("private key file is not a valid private key: %s", err)
	}
	return nil
}

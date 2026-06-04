//go:build e2etests

package auth

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
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awssso "github.com/aws/aws-sdk-go-v2/service/sso"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	ssoconfig "github.com/synfinatic/aws-sso-cli/internal/sso/config"
	"github.com/synfinatic/aws-sso-cli/internal/sso/oidc"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

// NewAWSSSOForTest creates an AWSSSO whose AWS SDK clients point to serverURL instead
// of real AWS endpoints. Only for use in integration tests.
func NewAWSSSOForTest(s *ssoconfig.SSOConfig, store storage.SecureStorage, serverURL string) *AWSSSO {
	r := retry.NewStandard(func(o *retry.StandardOptions) {
		o.MaxAttempts = 1
		o.MaxBackoff = 0
	})

	oidcAPI := ssooidc.New(ssooidc.Options{
		Region:       s.SSORegion,
		Retryer:      r,
		BaseEndpoint: aws.String(serverURL),
		Credentials:  aws.AnonymousCredentials{},
	})

	ssoSession := awssso.New(awssso.Options{
		Region:       s.SSORegion,
		Retryer:      r,
		BaseEndpoint: aws.String(serverURL),
		Credentials:  aws.AnonymousCredentials{},
	})

	return &AWSSSO{
		key:            s.GetKey(),
		sso:            ssoSession,
		oidcClient:     oidc.NewAWSWithAPI(oidcAPI),
		store:          store,
		ClientName:     awsSSOClientName,
		ClientType:     awsSSOClientType,
		SsoRegion:      s.SSORegion,
		StartUrl:       s.StartUrl,
		Roles:          map[string][]ssoconfig.RoleInfo{},
		SSOConfig:      s,
		urlAction:      s.UrlAction,
		browser:        s.Browser,
		urlExecCommand: s.UrlExecCommand,
		stsEndpoint:    serverURL,
	}
}

// NewAWSSSOForTestWithOIDCClient is like NewAWSSSOForTest but accepts a custom
// oidcClient. Only for use in integration tests.
func NewAWSSSOForTestWithOIDCClient(s *ssoconfig.SSOConfig, store storage.SecureStorage, serverURL string, oidcOverride oidc.Client) *AWSSSO {
	r := retry.NewStandard(func(o *retry.StandardOptions) {
		o.MaxAttempts = 1
		o.MaxBackoff = 0
	})

	ssoSession := awssso.New(awssso.Options{
		Region:       s.SSORegion,
		Retryer:      r,
		BaseEndpoint: aws.String(serverURL),
		Credentials:  aws.AnonymousCredentials{},
	})

	return &AWSSSO{
		key:            s.GetKey(),
		sso:            ssoSession,
		oidcClient:     oidcOverride,
		store:          store,
		ClientName:     awsSSOClientName,
		ClientType:     awsSSOClientType,
		SsoRegion:      s.SSORegion,
		StartUrl:       s.StartUrl,
		Roles:          map[string][]ssoconfig.RoleInfo{},
		SSOConfig:      s,
		urlAction:      s.UrlAction,
		browser:        s.Browser,
		urlExecCommand: s.UrlExecCommand,
		stsEndpoint:    serverURL,
	}
}

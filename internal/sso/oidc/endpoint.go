package oidc

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
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/synfinatic/aws-sso-cli/internal/awsendpoint"
)

// AuthorizationEndpoint returns the OIDC `/authorize` endpoint URL for the given
// SSO region. AWS does not return the authorization endpoint from RegisterClient,
// so we have to construct it ourselves.
//
// The host is resolved via the SDK's own endpoint rules instead of hardcoding the
// `amazonaws.com` suffix, so non-commercial partitions resolve correctly -- e.g.
// the AWS European Sovereign Cloud (`eusc-de-east-1`) lives under `amazonaws.eu`
// and China under `amazonaws.com.cn`.
//
// An empty region or a resolver failure returns an error rather than a guessed
// URL, so a misconfigured region surfaces as a clear error instead of a request
// to a non-existent host.
func AuthorizationEndpoint(region string) (string, error) {
	return authorizationEndpoint(region, ssooidc.NewDefaultEndpointResolverV2())
}

func authorizationEndpoint(region string, resolver ssooidc.EndpointResolverV2) (string, error) {
	if region == "" {
		return "", fmt.Errorf("cannot resolve authorization endpoint: empty region")
	}
	useFips := awsendpoint.UseFipsEndpoint()
	useDualStack := awsendpoint.UseDualStackEndpoint()
	ep, err := resolver.ResolveEndpoint(
		context.Background(),
		ssooidc.EndpointParameters{
			Region:       aws.String(region),
			UseFIPS:      aws.Bool(useFips),
			UseDualStack: aws.Bool(useDualStack),
		},
	)
	if err != nil {
		switch {
		case useFips && useDualStack:
			return "", fmt.Errorf("resolve FIPS dual-stack authorization endpoint for region %q: %w", region, err)
		case useFips:
			return "", fmt.Errorf("resolve FIPS authorization endpoint for region %q: %w", region, err)
		case useDualStack:
			return "", fmt.Errorf("resolve dual-stack authorization endpoint for region %q: %w", region, err)
		default:
			return "", fmt.Errorf("resolve authorization endpoint for region %q: %w", region, err)
		}
	}
	return strings.TrimSuffix(ep.URI.String(), "/") + "/authorize", nil
}

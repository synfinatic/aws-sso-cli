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
)

// AuthorizationEndpoint returns the OIDC `/authorize` endpoint URL for the given
// SSO region. AWS does not return the authorization endpoint from RegisterClient,
// so we have to construct it ourselves.
//
// The host is resolved via the SDK's own endpoint rules instead of hardcoding the
// `amazonaws.com` suffix, so non-commercial partitions resolve correctly -- e.g.
// the AWS European Sovereign Cloud (`eusc-de-east-1`) lives under `amazonaws.eu`
// and China under `amazonaws.com.cn`.
func AuthorizationEndpoint(region string) string {
	ep, err := ssooidc.NewDefaultEndpointResolverV2().ResolveEndpoint(
		context.Background(),
		ssooidc.EndpointParameters{Region: aws.String(region)},
	)
	if err != nil {
		// Fall back to the commercial partition host if the region is unknown
		// to the SDK's endpoint rules.
		return fmt.Sprintf("https://oidc.%s.amazonaws.com/authorize", region)
	}
	return strings.TrimSuffix(ep.URI.String(), "/") + "/authorize"
}

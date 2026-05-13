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
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

type AWSClient struct {
	api API
}

func NewAWS(region string, retryer aws.Retryer) *AWSClient {
	return &AWSClient{api: NewAWSAPI(region, retryer)}
}

func NewAWSAPI(region string, retryer aws.Retryer) API {
	return ssooidc.New(ssooidc.Options{Region: region, Retryer: retryer})
}

func NewAWSWithAPI(api API) *AWSClient {
	return &AWSClient{api: api}
}

func (c *AWSClient) RegisterClient(ctx context.Context, in RegisterClientInput) (storage.RegisterClientData, error) {
	input := &ssooidc.RegisterClientInput{
		ClientName:   aws.String(in.ClientName),
		ClientType:   aws.String(in.ClientType),
		GrantTypes:   in.GrantTypes,
		RedirectUris: in.RedirectUris,
		Scopes:       in.Scopes,
	}
	if in.IssuerUrl != "" {
		input.IssuerUrl = aws.String(in.IssuerUrl)
	}
	out, err := c.api.RegisterClient(ctx, input)
	if err != nil {
		return storage.RegisterClientData{}, fmt.Errorf("registerClient: %w", err)
	}
	log.Error("register client response: %v", out)

	return storage.RegisterClientData{
		AuthorizationEndpoint: aws.ToString(out.AuthorizationEndpoint),
		ClientId:              aws.ToString(out.ClientId),
		ClientSecret:          aws.ToString(out.ClientSecret),
		ClientIdIssuedAt:      out.ClientIdIssuedAt,
		ClientSecretExpiresAt: out.ClientSecretExpiresAt,
		TokenEndpoint:         aws.ToString(out.TokenEndpoint),
	}, nil
}

func (c *AWSClient) CreateToken(ctx context.Context, in CreateTokenInput) (storage.CreateTokenResponse, error) {
	input := &ssooidc.CreateTokenInput{
		ClientId:     aws.String(in.ClientID),
		ClientSecret: aws.String(in.ClientSecret),
		GrantType:    aws.String(string(in.GrantType)),
	}
	if in.DeviceCode != "" {
		input.DeviceCode = aws.String(in.DeviceCode)
	}
	if in.Code != "" {
		input.Code = aws.String(in.Code)
	}
	if in.CodeVerifier != "" {
		input.CodeVerifier = aws.String(in.CodeVerifier)
	}
	if in.RedirectURI != "" {
		input.RedirectUri = aws.String(in.RedirectURI)
	}
	if in.RefreshToken != "" {
		input.RefreshToken = aws.String(in.RefreshToken)
	}
	out, err := c.api.CreateToken(ctx, input)
	if err != nil {
		return storage.CreateTokenResponse{}, err
	}

	secs := time.Duration(out.ExpiresIn) * time.Second
	return storage.CreateTokenResponse{
		AccessToken:  aws.ToString(out.AccessToken),
		ExpiresIn:    out.ExpiresIn,
		ExpiresAt:    time.Now().Add(secs).Unix(),
		IdToken:      aws.ToString(out.IdToken),
		RefreshToken: aws.ToString(out.RefreshToken),
		TokenType:    aws.ToString(out.TokenType),
	}, nil
}

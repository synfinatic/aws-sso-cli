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
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	oidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

// API is the low-level AWS SSO OIDC client surface used by this package.
type API interface {
	RegisterClient(context.Context, *ssooidc.RegisterClientInput, ...func(*ssooidc.Options)) (*ssooidc.RegisterClientOutput, error)
	StartDeviceAuthorization(context.Context, *ssooidc.StartDeviceAuthorizationInput, ...func(*ssooidc.Options)) (*ssooidc.StartDeviceAuthorizationOutput, error)
	CreateToken(context.Context, *ssooidc.CreateTokenInput, ...func(*ssooidc.Options)) (*ssooidc.CreateTokenOutput, error)
}

// Client is the higher-level OIDC interface consumed by the sso package.
// It intentionally supports generic token creation input so additional
// workflows (for example PKCE authorization_code) can be added incrementally.
type Client interface {
	RegisterClient(context.Context, RegisterClientInput) (storage.RegisterClientData, error)
	StartDeviceAuthorization(context.Context, StartDeviceAuthorizationInput) (storage.StartDeviceAuthData, error)
	CreateToken(context.Context, CreateTokenInput) (storage.CreateTokenResponse, error)
	PollDeviceCodeToken(context.Context, PollDeviceCodeTokenInput) (storage.CreateTokenResponse, error)
}

type RegisterClientInput struct {
	ClientName string
	ClientType string
	GrantTypes []string
	Scopes     []string
}

type StartDeviceAuthorizationInput struct {
	StartURL     string
	ClientID     string
	ClientSecret string // nolint:gosec
}

type CreateTokenInput struct {
	ClientID     string
	ClientSecret string // nolint:gosec
	GrantType    string
	DeviceCode   string
	Code         string
	CodeVerifier string
	RedirectURI  string
}

type PollDeviceCodeTokenInput struct {
	CreateTokenInput
	RetryInterval time.Duration
	SlowDown      time.Duration
}

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
	out, err := c.api.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: aws.String(in.ClientName),
		ClientType: aws.String(in.ClientType),
		GrantTypes: in.GrantTypes,
		Scopes:     in.Scopes,
	})
	if err != nil {
		return storage.RegisterClientData{}, fmt.Errorf("registerClient: %w", err)
	}

	return storage.RegisterClientData{
		AuthorizationEndpoint: aws.ToString(out.AuthorizationEndpoint),
		ClientId:              aws.ToString(out.ClientId),
		ClientSecret:          aws.ToString(out.ClientSecret),
		ClientIdIssuedAt:      out.ClientIdIssuedAt,
		ClientSecretExpiresAt: out.ClientSecretExpiresAt,
		TokenEndpoint:         aws.ToString(out.TokenEndpoint),
	}, nil
}

func (c *AWSClient) StartDeviceAuthorization(ctx context.Context, in StartDeviceAuthorizationInput) (storage.StartDeviceAuthData, error) {
	out, err := c.api.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		StartUrl:     aws.String(in.StartURL),
		ClientId:     aws.String(in.ClientID),
		ClientSecret: aws.String(in.ClientSecret),
	})
	if err != nil {
		return storage.StartDeviceAuthData{}, err
	}

	return storage.StartDeviceAuthData{
		DeviceCode:              aws.ToString(out.DeviceCode),
		UserCode:                aws.ToString(out.UserCode),
		VerificationUri:         aws.ToString(out.VerificationUri),
		VerificationUriComplete: aws.ToString(out.VerificationUriComplete),
		ExpiresIn:               out.ExpiresIn,
		Interval:                out.Interval,
	}, nil
}

func (c *AWSClient) CreateToken(ctx context.Context, in CreateTokenInput) (storage.CreateTokenResponse, error) {
	out, err := c.api.CreateToken(ctx, &ssooidc.CreateTokenInput{
		ClientId:     aws.String(in.ClientID),
		ClientSecret: aws.String(in.ClientSecret),
		GrantType:    aws.String(in.GrantType),
		DeviceCode:   aws.String(in.DeviceCode),
		Code:         aws.String(in.Code),
		CodeVerifier: aws.String(in.CodeVerifier),
		RedirectUri:  aws.String(in.RedirectURI),
	})
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

func (c *AWSClient) PollDeviceCodeToken(ctx context.Context, in PollDeviceCodeTokenInput) (storage.CreateTokenResponse, error) {
	retryInterval := in.RetryInterval
	if retryInterval <= 0 {
		retryInterval = 5 * time.Second
	}

	slowDown := in.SlowDown
	if slowDown <= 0 {
		slowDown = 5 * time.Second
	}

	for {
		token, err := c.CreateToken(ctx, in.CreateTokenInput)
		if err == nil {
			return token, nil
		}

		var sde *oidctypes.SlowDownException
		var ape *oidctypes.AuthorizationPendingException

		switch {
		case errors.As(err, &sde):
			retryInterval += slowDown
			if err = sleepWithContext(ctx, retryInterval); err != nil {
				return storage.CreateTokenResponse{}, err
			}
		case errors.As(err, &ape):
			if err = sleepWithContext(ctx, retryInterval); err != nil {
				return storage.CreateTokenResponse{}, err
			}
		default:
			return storage.CreateTokenResponse{}, fmt.Errorf("createToken: %w", err)
		}
	}
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

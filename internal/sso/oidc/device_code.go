package oidc

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

package oidc

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	oidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	"github.com/stretchr/testify/assert"
)

func TestStartDeviceAuthorization(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		api := &mockOIDCAPI{
			startDeviceAuthOutput: &ssooidc.StartDeviceAuthorizationOutput{
				DeviceCode:              aws.String("dev-code"),
				UserCode:                aws.String("user-code"),
				VerificationUri:         aws.String("https://verify.example.com"),
				VerificationUriComplete: aws.String("https://verify.example.com/full"),
				ExpiresIn:               30,
				Interval:                2,
			},
		}

		client := NewAWSWithAPI(api)
		out, err := client.StartDeviceAuthorization(context.Background(), StartDeviceAuthorizationInput{
			StartURL:     "https://start.example.com",
			ClientID:     "client-id",
			ClientSecret: "client-secret",
		})

		assert.NoError(t, err)
		if assert.Len(t, api.startDeviceAuthInputs, 1) {
			assert.Equal(t, "https://start.example.com", aws.ToString(api.startDeviceAuthInputs[0].StartUrl))
			assert.Equal(t, "client-id", aws.ToString(api.startDeviceAuthInputs[0].ClientId))
			assert.Equal(t, "client-secret", aws.ToString(api.startDeviceAuthInputs[0].ClientSecret))
		}

		assert.Equal(t, "dev-code", out.DeviceCode)
		assert.Equal(t, "user-code", out.UserCode)
		assert.Equal(t, "https://verify.example.com", out.VerificationUri)
		assert.Equal(t, "https://verify.example.com/full", out.VerificationUriComplete)
		assert.Equal(t, int32(30), out.ExpiresIn)
		assert.Equal(t, int32(2), out.Interval)
	})

	t.Run("error passthrough", func(t *testing.T) {
		api := &mockOIDCAPI{startDeviceAuthErr: errors.New("device auth failed")}
		client := NewAWSWithAPI(api)

		_, err := client.StartDeviceAuthorization(context.Background(), StartDeviceAuthorizationInput{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "device auth failed")
	})
}

func TestPollDeviceCodeToken(t *testing.T) {
	t.Run("authorization pending then success", func(t *testing.T) {
		api := &mockOIDCAPI{
			createTokenOutputs: []*ssooidc.CreateTokenOutput{
				nil,
				{
					AccessToken: aws.String("ok"),
					ExpiresIn:   60,
				},
			},
			createTokenErrors: []error{
				&oidctypes.AuthorizationPendingException{},
				nil,
			},
		}
		client := NewAWSWithAPI(api)

		out, err := client.PollDeviceCodeToken(context.Background(), PollDeviceCodeTokenInput{
			CreateTokenInput: CreateTokenInput{ClientID: "cid", GrantType: "device"},
			RetryInterval:    time.Millisecond,
			SlowDown:         time.Millisecond,
		})

		assert.NoError(t, err)
		assert.Equal(t, "ok", out.AccessToken)
		assert.Len(t, api.createTokenInputs, 2)
	})

	t.Run("slow down then success", func(t *testing.T) {
		api := &mockOIDCAPI{
			createTokenOutputs: []*ssooidc.CreateTokenOutput{
				nil,
				{
					AccessToken: aws.String("ok2"),
					ExpiresIn:   60,
				},
			},
			createTokenErrors: []error{
				&oidctypes.SlowDownException{},
				nil,
			},
		}
		client := NewAWSWithAPI(api)

		out, err := client.PollDeviceCodeToken(context.Background(), PollDeviceCodeTokenInput{
			CreateTokenInput: CreateTokenInput{ClientID: "cid", GrantType: "device"},
			RetryInterval:    time.Millisecond,
			SlowDown:         time.Millisecond,
		})

		assert.NoError(t, err)
		assert.Equal(t, "ok2", out.AccessToken)
		assert.Len(t, api.createTokenInputs, 2)
	})

	t.Run("unexpected error wrapped", func(t *testing.T) {
		api := &mockOIDCAPI{
			createTokenErrors: []error{errors.New("bad-token")},
		}
		client := NewAWSWithAPI(api)

		_, err := client.PollDeviceCodeToken(context.Background(), PollDeviceCodeTokenInput{
			CreateTokenInput: CreateTokenInput{ClientID: "cid", GrantType: "device"},
			RetryInterval:    time.Millisecond,
			SlowDown:         time.Millisecond,
		})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "createToken:")
		assert.Contains(t, err.Error(), "bad-token")
	})

	t.Run("context canceled while waiting", func(t *testing.T) {
		api := &mockOIDCAPI{
			createTokenErrors: []error{&oidctypes.AuthorizationPendingException{}},
		}
		client := NewAWSWithAPI(api)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := client.PollDeviceCodeToken(ctx, PollDeviceCodeTokenInput{
			CreateTokenInput: CreateTokenInput{ClientID: "cid", GrantType: "device"},
			// Leave interval values at zero to exercise defaulting without incurring delay.
		})

		assert.Error(t, err)
		assert.True(t, errors.Is(err, context.Canceled), fmt.Sprintf("expected context canceled, got: %v", err))
		assert.Len(t, api.createTokenInputs, 1)
	})
}

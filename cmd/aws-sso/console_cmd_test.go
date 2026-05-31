package main

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHaveAWSEnvVars(t *testing.T) {
	t.Run("all three fields set: true", func(t *testing.T) {
		ctx := &RunContext{
			Cli: &CLI{
				Console: ConsoleCmd{
					AccessKeyId:     "AKIATEST",
					SecretAccessKey: "secretkey",
					SessionToken:    "sessiontoken",
				},
			},
		}
		assert.True(t, haveAWSEnvVars(ctx))
	})

	t.Run("missing AccessKeyId: false", func(t *testing.T) {
		ctx := &RunContext{
			Cli: &CLI{
				Console: ConsoleCmd{
					SecretAccessKey: "secretkey",
					SessionToken:    "sessiontoken",
				},
			},
		}
		assert.False(t, haveAWSEnvVars(ctx))
	})

	t.Run("missing SecretAccessKey: false", func(t *testing.T) {
		ctx := &RunContext{
			Cli: &CLI{
				Console: ConsoleCmd{
					AccessKeyId:  "AKIATEST",
					SessionToken: "sessiontoken",
				},
			},
		}
		assert.False(t, haveAWSEnvVars(ctx))
	})

	t.Run("missing SessionToken: false", func(t *testing.T) {
		ctx := &RunContext{
			Cli: &CLI{
				Console: ConsoleCmd{
					AccessKeyId:     "AKIATEST",
					SecretAccessKey: "secretkey",
				},
			},
		}
		assert.False(t, haveAWSEnvVars(ctx))
	})

	t.Run("all empty: false", func(t *testing.T) {
		ctx := &RunContext{Cli: &CLI{}}
		assert.False(t, haveAWSEnvVars(ctx))
	})
}

func TestSigninTokenUrlParamsGetUrl(t *testing.T) {
	params := SigninTokenUrlParams{
		SsoRegion:       "us-east-1",
		SessionDuration: 3600,
		Session: SessionUrlParams{
			AccessKeyId:     "AKIATEST",
			SecretAccessKey: "secretkey",
			SessionToken:    "sessiontoken",
		},
	}

	t.Run("without role chaining: includes SessionDuration", func(t *testing.T) {
		u := params.GetUrl(false)
		assert.Contains(t, u, "Action=getSigninToken")
		assert.Contains(t, u, "SessionDuration=3600")
		assert.NotContains(t, u, "SessionDuration=0") // sanity: duration is passed through
	})

	t.Run("with role chaining: omits SessionDuration", func(t *testing.T) {
		u := params.GetUrl(true)
		assert.Contains(t, u, "Action=getSigninToken")
		assert.NotContains(t, u, "SessionDuration")
	})

	t.Run("both variants include Session parameter", func(t *testing.T) {
		u1 := params.GetUrl(false)
		u2 := params.GetUrl(true)
		assert.Contains(t, u1, "Session=")
		assert.Contains(t, u2, "Session=")
	})
}

func TestSessionUrlParamsEncode(t *testing.T) {
	sup := SessionUrlParams{
		AccessKeyId:     "AKIATEST123",
		SecretAccessKey: "MySecretKey",
		SessionToken:    "MySessionToken",
	}

	encoded := sup.Encode()
	assert.NotEmpty(t, encoded)

	// URL-decode and then JSON-decode to check field names.
	decoded, err := url.QueryUnescape(encoded)
	assert.NoError(t, err)

	var result map[string]string
	err = json.Unmarshal([]byte(decoded), &result)
	assert.NoError(t, err)

	assert.Equal(t, "AKIATEST123", result["sessionId"])
	assert.Equal(t, "MySecretKey", result["sessionKey"])
	assert.Equal(t, "MySessionToken", result["sessionToken"])
}

func TestLoginUrlParamsGetUrl(t *testing.T) {
	lup := LoginUrlParams{
		SsoRegion:   "us-east-1",
		Issuer:      "https://example.awsapps.com/start",
		Destination: "https://console.aws.amazon.com/",
		SigninToken: "abc123token",
	}

	u := lup.GetUrl()

	assert.Contains(t, u, "Action=login")
	assert.Contains(t, u, "Issuer=")
	assert.Contains(t, u, "Destination=")
	assert.Contains(t, u, "SigninToken=abc123token")
	assert.True(t, strings.HasPrefix(u, "https://"), "URL should start with https://")
}

package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

func TestNewCredentialsProcessOutput(t *testing.T) {
	// Expiration is stored as milliseconds since epoch.
	expMs := int64(1700000000000)
	creds := &storage.RoleCredentials{
		RoleName:        "MyRole",
		AccountId:       123456789012,
		AccessKeyId:     "AKIATEST123",
		SecretAccessKey: "secretkey",
		SessionToken:    "sessiontoken",
		Expiration:      expMs,
	}

	out := NewCredentialsProcessOutput(creds)

	assert.Equal(t, 1, out.Version)
	assert.Equal(t, "AKIATEST123", out.AccessKeyId)
	assert.Equal(t, "secretkey", out.SecretAccessKey)
	assert.Equal(t, "sessiontoken", out.SessionToken)

	// Verify RFC3339 format
	expectedTime := time.Unix(expMs/1000, 0).Format(time.RFC3339)
	assert.Equal(t, expectedTime, out.Expiration)
}

func TestCredentialProcessOutputOutput(t *testing.T) {
	cpo := &CredentialProcessOutput{
		Version:         1,
		AccessKeyId:     "AKIATEST",
		SecretAccessKey: "mysecret",
		SessionToken:    "mytoken",
		Expiration:      "2023-11-14T22:13:20Z",
	}

	s, err := cpo.Output()
	assert.NoError(t, err)
	assert.NotEmpty(t, s)

	// Verify it round-trips as valid JSON with the right field names.
	var parsed map[string]interface{}
	err = json.Unmarshal([]byte(s), &parsed)
	assert.NoError(t, err)
	assert.Equal(t, float64(1), parsed["Version"])
	assert.Equal(t, "AKIATEST", parsed["AccessKeyId"])
	assert.Equal(t, "mysecret", parsed["SecretAccessKey"])
	assert.Equal(t, "mytoken", parsed["SessionToken"])
	assert.Equal(t, "2023-11-14T22:13:20Z", parsed["Expiration"])
}

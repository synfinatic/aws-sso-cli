package main

import (
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureTimeCmdStdout redirects os.Stdout for the duration of fn and returns what was written.
func captureTimeCmdStdout(fn func()) string {
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	old := os.Stdout
	os.Stdout = w
	func() {
		defer func() {
			w.Close()
			os.Stdout = old
		}()
		fn()
	}()
	buf, _ := io.ReadAll(r)
	r.Close()
	return string(buf)
}

func TestTimeCmdAfterApply(t *testing.T) {
	ctx := &RunContext{Cli: &CLI{}}
	cmd := TimeCmd{}
	require.NoError(t, cmd.AfterApply(ctx))
	assert.Equal(t, AUTH_SKIP, ctx.Auth)
}

func TestTimeCmdRun_NoEnvVar(t *testing.T) {
	unsetEnvForTest(t, "AWS_SSO_SESSION_EXPIRATION")
	ctx := &RunContext{Cli: &CLI{}}
	cmd := &TimeCmd{}
	output := captureTimeCmdStdout(func() {
		assert.NoError(t, cmd.Run(ctx))
	})
	assert.Empty(t, output)
}

func TestTimeCmdRun_FutureTime(t *testing.T) {
	future := time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)
	t.Setenv("AWS_SSO_SESSION_EXPIRATION", future)

	ctx := &RunContext{Cli: &CLI{}}
	cmd := &TimeCmd{}
	output := captureTimeCmdStdout(func() {
		assert.NoError(t, cmd.Run(ctx))
	})
	assert.NotEmpty(t, output)
}

func TestTimeCmdRun_InvalidTime(t *testing.T) {
	t.Setenv("AWS_SSO_SESSION_EXPIRATION", "not-a-valid-time")
	ctx := &RunContext{Cli: &CLI{}}
	cmd := &TimeCmd{}
	assert.Error(t, cmd.Run(ctx))
}

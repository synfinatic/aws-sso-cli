package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogoutCmdAfterApply(t *testing.T) {
	ctx := &RunContext{Cli: &CLI{}}
	cmd := LogoutCmd{}
	require.NoError(t, cmd.AfterApply(ctx))
	assert.Equal(t, AUTH_SKIP, ctx.Auth)
}

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInvalidArgsError(t *testing.T) {
	t.Run("with arg field uses Sprintf format", func(t *testing.T) {
		e := &InvalidArgsError{msg: "Invalid --profile %s", arg: "bad-profile"}
		assert.Equal(t, "Invalid --profile bad-profile", e.Error())
	})

	t.Run("without arg field returns plain message", func(t *testing.T) {
		e := &InvalidArgsError{msg: "Must specify both --account and --role"}
		assert.Equal(t, "Must specify both --account and --role", e.Error())
	})
}

func TestNoRoleSelectedError(t *testing.T) {
	e := &NoRoleSelectedError{}
	assert.Equal(t, "Unable to select role", e.Error())
}

func TestSelectCliArgsUpdate_Arn(t *testing.T) {
	ctx := &RunContext{Cli: &CLI{}}

	t.Run("valid full ARN parses account and role", func(t *testing.T) {
		a := NewSelectCliArgs("arn:aws:iam::123456789012:role/MyRole", 0, "", "")
		err := a.Update(ctx)
		assert.NoError(t, err)
		assert.Equal(t, int64(123456789012), a.AccountId)
		assert.Equal(t, "MyRole", a.RoleName)
	})

	t.Run("valid short account:role ARN parses correctly", func(t *testing.T) {
		a := NewSelectCliArgs("123456789012:MyRole", 0, "", "")
		err := a.Update(ctx)
		assert.NoError(t, err)
		assert.Equal(t, int64(123456789012), a.AccountId)
		assert.Equal(t, "MyRole", a.RoleName)
	})

	t.Run("invalid ARN returns InvalidArgsError", func(t *testing.T) {
		a := NewSelectCliArgs("not-an-arn", 0, "", "")
		err := a.Update(ctx)
		assert.Error(t, err)
		var iErr *InvalidArgsError
		assert.ErrorAs(t, err, &iErr)
	})
}

func TestSelectCliArgsUpdate_AccountRole(t *testing.T) {
	ctx := &RunContext{Cli: &CLI{}}

	t.Run("both account and role set: success", func(t *testing.T) {
		a := NewSelectCliArgs("", 123456789012, "MyRole", "")
		err := a.Update(ctx)
		assert.NoError(t, err)
	})

	t.Run("only account set: InvalidArgsError", func(t *testing.T) {
		a := NewSelectCliArgs("", 123456789012, "", "")
		err := a.Update(ctx)
		assert.Error(t, err)
		var iErr *InvalidArgsError
		assert.ErrorAs(t, err, &iErr)
	})

	t.Run("only role set: InvalidArgsError", func(t *testing.T) {
		a := NewSelectCliArgs("", 0, "MyRole", "")
		err := a.Update(ctx)
		assert.Error(t, err)
		var iErr *InvalidArgsError
		assert.ErrorAs(t, err, &iErr)
	})
}

func TestSelectCliArgsUpdate_NoArgs(t *testing.T) {
	ctx := &RunContext{Cli: &CLI{}}
	a := NewSelectCliArgs("", 0, "", "")
	err := a.Update(ctx)
	assert.Error(t, err)
	var nErr *NoRoleSelectedError
	assert.ErrorAs(t, err, &nErr)
}

func TestSelectCliArgsUpdate_EnvArnVsAccountRole(t *testing.T) {
	ctx := &RunContext{Cli: &CLI{}}
	envArn := "arn:aws:iam::111111111111:role/EnvRole"

	t.Run("ARN from env loses to explicit account and role", func(t *testing.T) {
		t.Setenv("AWS_SSO_ROLE_ARN", envArn)
		a := NewSelectCliArgs(envArn, 222222222222, "FlagRole", "")
		assert.NoError(t, a.Update(ctx))
		assert.Equal(t, int64(222222222222), a.AccountId)
		assert.Equal(t, "FlagRole", a.RoleName)
	})

	t.Run("explicit --arn wins over account and role", func(t *testing.T) {
		t.Setenv("AWS_SSO_ROLE_ARN", "")
		a := NewSelectCliArgs(envArn, 222222222222, "FlagRole", "")
		assert.NoError(t, a.Update(ctx))
		assert.Equal(t, int64(111111111111), a.AccountId)
		assert.Equal(t, "EnvRole", a.RoleName)
	})

	t.Run("ARN from env alone is still used", func(t *testing.T) {
		t.Setenv("AWS_SSO_ROLE_ARN", envArn)
		a := NewSelectCliArgs(envArn, 0, "", "")
		assert.NoError(t, a.Update(ctx))
		assert.Equal(t, int64(111111111111), a.AccountId)
		assert.Equal(t, "EnvRole", a.RoleName)
	})

	t.Run("ARN from env with only one of account or role is still used", func(t *testing.T) {
		t.Setenv("AWS_SSO_ROLE_ARN", envArn)
		a := NewSelectCliArgs(envArn, 222222222222, "", "")
		assert.NoError(t, a.Update(ctx))
		assert.Equal(t, int64(111111111111), a.AccountId)
		assert.Equal(t, "EnvRole", a.RoleName)
	})

	t.Run("only account set without ARN: InvalidArgsError", func(t *testing.T) {
		t.Setenv("AWS_SSO_ROLE_ARN", "")
		a := NewSelectCliArgs("", 222222222222, "", "")
		var iErr *InvalidArgsError
		assert.ErrorAs(t, a.Update(ctx), &iErr)
	})
}

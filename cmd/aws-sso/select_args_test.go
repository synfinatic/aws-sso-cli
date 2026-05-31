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

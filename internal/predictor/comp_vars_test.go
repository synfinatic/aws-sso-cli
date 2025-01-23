package predictor

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2025 Aaron Turner  <synfinatic at gmail dot com>
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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetSSOFlag(t *testing.T) {
	defer func() { os.Unsetenv("COMP_LINE") }()

	os.Setenv("COMP_LINE", "aws-sso eval -S Default -R")
	assert.Equal(t, "Default", getSSOFlag())

	os.Setenv("COMP_LINE", "aws-sso eval --sso Default -R")
	assert.Equal(t, "Default", getSSOFlag())

	os.Setenv("COMP_LINE", "aws-sso eval --so Default -R")
	assert.Equal(t, "", getSSOFlag())
}

func TestGetAccountIdFlag(t *testing.T) {
	defer func() { os.Unsetenv("COMP_LINE") }()

	os.Setenv("COMP_LINE", "aws-sso eval -A 5555 -R")
	assert.Equal(t, int64(5555), getAccountIdFlag())

	os.Setenv("COMP_LINE", "aws-sso eval --account 5555 -R")
	assert.Equal(t, int64(5555), getAccountIdFlag())

	os.Setenv("COMP_LINE", "aws-sso eval --account -5555 -R")
	assert.Equal(t, int64(-5555), getAccountIdFlag())

	os.Setenv("COMP_LINE", "aws-sso eval --accoun 5555 -R")
	assert.Equal(t, int64(-1), getAccountIdFlag())
}

func TestGetRoleFlag(t *testing.T) {
	defer func() { os.Unsetenv("COMP_LINE") }()

	os.Setenv("COMP_LINE", "aws-sso eval -R Default -A")
	assert.Equal(t, "Default", getRoleFlag())

	os.Setenv("COMP_LINE", "aws-sso eval --role Default -A")
	assert.Equal(t, "Default", getRoleFlag())

	os.Setenv("COMP_LINE", "aws-sso eval --rol Default -A")
	assert.Equal(t, "", getRoleFlag())
}

func TestFlagValue(t *testing.T) {
	flags := []string{"-S", "--sso"}

	assert.Equal(t, "", flagValue("", flags))
	assert.Equal(t, "", flagValue("aws-sso eval -S", flags))
	assert.Equal(t, "", flagValue("aws-sso eval -S D", flags))
	assert.Equal(t, "", flagValue("aws-sso eval -S Default", flags))
	assert.Equal(t, "Default", flagValue("aws-sso eval -S Default ", flags))
}

//go:build e2etests

package main

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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2ETagsCmd_AllRoles verifies that TagsCmd.Run prints all roles when no filter is set.
func TestE2ETagsCmd_AllRoles(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)

	ctx := newRunContext(setup, AUTH_SKIP)

	output := captureStdout(func() {
		require.NoError(t, (&TagsCmd{}).Run(ctx))
	})

	assert.Contains(t, output, "arn:aws:iam::123456789012:role/ReadOnly")
	assert.Contains(t, output, "arn:aws:iam::123456789012:role/PowerUser")
}

// TestE2ETagsCmd_FilterByAccount verifies that specifying an AccountId shows only roles for
// that account.
func TestE2ETagsCmd_FilterByAccount(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)

	ctx := newRunContext(setup, AUTH_SKIP)
	ctx.Cli.Tags = TagsCmd{AccountId: AccountID(123456789012)}

	output := captureStdout(func() {
		require.NoError(t, (&TagsCmd{}).Run(ctx))
	})

	assert.Contains(t, output, "arn:aws:iam::123456789012:role/ReadOnly")
	assert.Contains(t, output, "arn:aws:iam::123456789012:role/PowerUser")
}

// TestE2ETagsCmd_FilterByRole verifies that specifying a Role name shows only that role.
func TestE2ETagsCmd_FilterByRole(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)

	ctx := newRunContext(setup, AUTH_SKIP)
	ctx.Cli.Tags = TagsCmd{Role: "ReadOnly"}

	output := captureStdout(func() {
		require.NoError(t, (&TagsCmd{}).Run(ctx))
	})

	assert.Contains(t, output, "arn:aws:iam::123456789012:role/ReadOnly")
	assert.NotContains(t, output, "PowerUser")
}

// TestE2ETagsCmd_FilterByBoth verifies that specifying both AccountId and Role narrows results.
func TestE2ETagsCmd_FilterByBoth(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)

	ctx := newRunContext(setup, AUTH_SKIP)
	ctx.Cli.Tags = TagsCmd{
		AccountId: AccountID(123456789012),
		Role:      "PowerUser",
	}

	output := captureStdout(func() {
		require.NoError(t, (&TagsCmd{}).Run(ctx))
	})

	assert.Contains(t, output, "arn:aws:iam::123456789012:role/PowerUser")
	assert.NotContains(t, output, "ReadOnly")
}

// TestE2ETagsCmd_NoMatchingAccount verifies that a non-existent account produces no output.
func TestE2ETagsCmd_NoMatchingAccount(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)

	ctx := newRunContext(setup, AUTH_SKIP)
	ctx.Cli.Tags = TagsCmd{AccountId: AccountID(999999999999)}

	output := captureStdout(func() {
		require.NoError(t, (&TagsCmd{}).Run(ctx))
	})

	assert.Empty(t, output)
}

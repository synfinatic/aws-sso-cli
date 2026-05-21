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
)

func TestSetRegionVars(t *testing.T) {
	t.Run("sets AWS_DEFAULT_REGION, AWS_REGION and sentinel when region is non-empty", func(t *testing.T) {
		shellVars := map[string]string{}
		setRegionVars(shellVars, "us-east-1")
		assert.Equal(t, "us-east-1", shellVars["AWS_DEFAULT_REGION"])
		assert.Equal(t, "us-east-1", shellVars["AWS_REGION"])
		assert.Equal(t, "us-east-1", shellVars["AWS_SSO_DEFAULT_REGION"])
	})

	t.Run("clears sentinel and leaves region vars absent when region is empty", func(t *testing.T) {
		shellVars := map[string]string{}
		setRegionVars(shellVars, "")
		assert.NotContains(t, shellVars, "AWS_DEFAULT_REGION")
		assert.NotContains(t, shellVars, "AWS_REGION")
		assert.Equal(t, "", shellVars["AWS_SSO_DEFAULT_REGION"])
	})
}

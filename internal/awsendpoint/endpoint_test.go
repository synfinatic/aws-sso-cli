package awsendpoint

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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
)

func TestUseFipsEndpoint(t *testing.T) {
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "true")
	assert.True(t, UseFipsEndpoint())

	t.Setenv("AWS_USE_FIPS_ENDPOINT", "1")
	assert.True(t, UseFipsEndpoint())

	t.Setenv("AWS_USE_FIPS_ENDPOINT", "false")
	assert.False(t, UseFipsEndpoint())

	t.Setenv("AWS_USE_FIPS_ENDPOINT", "0")
	assert.False(t, UseFipsEndpoint())

	// invalid values — must default to false and not panic
	for _, bad := range []string{"", "yes-please", "ENABLED"} {
		t.Setenv("AWS_USE_FIPS_ENDPOINT", bad)
		assert.False(t, UseFipsEndpoint(), "value=%q", bad)
	}
}

func TestFipsEndpointState(t *testing.T) {
	t.Setenv("AWS_USE_FIPS_ENDPOINT", "true")
	assert.Equal(t, aws.FIPSEndpointStateEnabled, FipsEndpointState())

	t.Setenv("AWS_USE_FIPS_ENDPOINT", "false")
	assert.Equal(t, aws.FIPSEndpointStateDisabled, FipsEndpointState())
}

func TestUseDualStackEndpoint(t *testing.T) {
	t.Setenv("AWS_USE_DUALSTACK_ENDPOINT", "true")
	assert.True(t, UseDualStackEndpoint())

	t.Setenv("AWS_USE_DUALSTACK_ENDPOINT", "1")
	assert.True(t, UseDualStackEndpoint())

	t.Setenv("AWS_USE_DUALSTACK_ENDPOINT", "false")
	assert.False(t, UseDualStackEndpoint())

	t.Setenv("AWS_USE_DUALSTACK_ENDPOINT", "0")
	assert.False(t, UseDualStackEndpoint())

	// invalid values — must default to false and not panic
	for _, bad := range []string{"", "yes-please", "ENABLED"} {
		t.Setenv("AWS_USE_DUALSTACK_ENDPOINT", bad)
		assert.False(t, UseDualStackEndpoint(), "value=%q", bad)
	}
}

func TestDualStackEndpointState(t *testing.T) {
	t.Setenv("AWS_USE_DUALSTACK_ENDPOINT", "true")
	assert.Equal(t, aws.DualStackEndpointStateEnabled, DualStackEndpointState())

	t.Setenv("AWS_USE_DUALSTACK_ENDPOINT", "false")
	assert.Equal(t, aws.DualStackEndpointStateDisabled, DualStackEndpointState())
}

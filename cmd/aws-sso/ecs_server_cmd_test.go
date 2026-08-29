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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ssocache "github.com/synfinatic/aws-sso-cli/internal/sso/cache"
)

func TestCertExpiryWarning(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		notAfter time.Time
		want     string
	}{
		{
			name:     "far from expiring",
			notAfter: now.Add(60 * 24 * time.Hour),
			want:     "",
		},
		{
			name:     "exactly at the warning window",
			notAfter: now.Add(ecsCertExpiryWarningWindow),
			want:     "",
		},
		{
			name:     "just inside the warning window",
			notAfter: now.Add(ecsCertExpiryWarningWindow - time.Second),
			want:     "SSL/TLS leaf certificate expires soon",
		},
		{
			name:     "expires right now",
			notAfter: now,
			want:     "SSL/TLS leaf certificate has expired",
		},
		{
			name:     "already expired",
			notAfter: now.Add(-24 * time.Hour),
			want:     "SSL/TLS leaf certificate has expired",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := certExpiryWarning("leaf certificate", tt.notAfter, now, ecsCertExpiryWarningWindow)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEcsServerCmdAfterApply(t *testing.T) {
	tests := []struct {
		name     string
		cmd      EcsServerCmd
		wantAuth CommandAuth
	}{
		{
			name:     "docker mode ignores Default",
			cmd:      EcsServerCmd{Docker: true, Default: "any-profile"},
			wantAuth: AUTH_NO_CONFIG,
		},
		{
			name:     "Default set without docker requires auth",
			cmd:      EcsServerCmd{Default: "my-profile"},
			wantAuth: AUTH_REQUIRED,
		},
		{
			name:     "no Default and no docker skips auth",
			cmd:      EcsServerCmd{},
			wantAuth: AUTH_SKIP,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runCtx := &RunContext{}
			err := tt.cmd.AfterApply(runCtx)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAuth, runCtx.Auth)
		})
	}
}

func TestSetServerDefaultProfileNotFound(t *testing.T) {
	// Build a RunContext with an empty SSO cache so GetRoleByProfile returns "not found".
	c := &ssocache.Cache{SSO: map[string]*ssocache.SSOCache{}}
	ctx := &RunContext{
		Settings: newMinimalSettings(c),
		Cli:      &CLI{},
	}
	// s can be nil: the function returns before touching the server on error.
	err := setServerDefaultProfile(ctx, nil, "nonexistent-profile")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent-profile")
}

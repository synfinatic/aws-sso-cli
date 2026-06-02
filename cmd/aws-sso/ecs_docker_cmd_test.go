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
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ssocache "github.com/synfinatic/aws-sso-cli/internal/sso/cache"
)

func TestEcsDockerStartCmdAfterApply(t *testing.T) {
	tests := []struct {
		name     string
		cmd      EcsDockerStartCmd
		wantAuth CommandAuth
	}{
		{
			name:     "Default set requires auth",
			cmd:      EcsDockerStartCmd{Default: "my-profile"},
			wantAuth: AUTH_REQUIRED,
		},
		{
			name:     "no Default skips auth",
			cmd:      EcsDockerStartCmd{},
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

func TestWaitForEcsHealthcheck_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Extract host:port from the test server URL.
	addr := strings.TrimPrefix(srv.URL, "http://")
	err := waitForEcsHealthcheck("http", addr, "", 2*time.Second)
	assert.NoError(t, err)
}

func TestWaitForEcsHealthcheck_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	err := waitForEcsHealthcheck("http", addr, "", 50*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not become healthy")
}

func TestWaitForEcsServerUp_Ready(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable) // 503 = server up, no creds yet
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	err := waitForEcsServerUp("http", addr, "", 2*time.Second)
	assert.NoError(t, err)
}

func TestWaitForEcsServerUp_Timeout(t *testing.T) {
	// Reserve an ephemeral port then immediately release it so we have an address
	// guaranteed not to be listening when waitForEcsServerUp is called.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	ln.Close()

	err = waitForEcsServerUp("http", addr, "", 50*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not start")
}

func TestLoadProfileToEcsServerNotFound(t *testing.T) {
	c := &ssocache.Cache{SSO: map[string]*ssocache.SSOCache{}}
	ctx := &RunContext{
		Settings: newMinimalSettings(c),
		Cli:      &CLI{},
	}
	err := loadProfileToEcsServer(ctx, "nonexistent-profile", "localhost:4144")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent-profile")
}

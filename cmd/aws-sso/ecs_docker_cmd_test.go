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
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/synfinatic/aws-sso-cli/internal/certutil"
	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	ssocache "github.com/synfinatic/aws-sso-cli/internal/sso/cache"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

// genTestCA creates a throwaway CA PEM certificate/key pair, valid enough to
// pass SaveEcsCaKeyPair's x509 validation and to sign leaves via
// certutil.GenerateLeaf.
func genTestCA(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	ca, err := certutil.GenerateCA()
	require.NoError(t, err)
	return ca.CertPEM, ca.KeyPEM
}

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

func TestEcsDockerSecretsCmdAfterApply(t *testing.T) {
	runCtx := &RunContext{}
	err := EcsDockerSecretsCmd{}.AfterApply(runCtx)
	require.NoError(t, err)
	assert.Equal(t, AUTH_SKIP, runCtx.Auth)
}

func TestEcsDockerSecretsCmdRun(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".config", "aws-sso"), 0700))
	t.Setenv("HOME", home)
	unsetXDGConfigHomeForTest(t)

	store, err := storage.OpenJsonStore(context.Background(), filepath.Join(home, "store.json"))
	require.NoError(t, err)

	caCertPEM, caKeyPEM := genTestCA(t)
	require.NoError(t, store.SaveEcsBearerToken(context.Background(), "s3cr3t"))
	require.NoError(t, store.SaveEcsCaKeyPair(context.Background(), []byte(caKeyPEM), []byte(caCertPEM)))

	ctx := &RunContext{Store: store, Cli: &CLI{}}
	cc := &EcsDockerSecretsCmd{}
	require.NoError(t, cc.Run(ctx))

	path := filepath.Join(home, ".config", "aws-sso", "ecs", "docker-secret.json")
	data, err := os.ReadFile(path) // nolint:gosec
	require.NoError(t, err)

	sec := &ecs.ECSSecurity{}
	require.NoError(t, json.Unmarshal(data, sec))
	assert.Equal(t, "s3cr3t", sec.BearerToken)
	assert.NotEmpty(t, sec.PrivateKey)
	assert.NotEmpty(t, sec.CertChain)

	// The written leaf must chain-verify against the stored CA -- it's
	// minted fresh, not a byte-for-byte copy of anything persisted.
	caCert := parsePEMCertForTest(t, caCertPEM)
	leafCert := parsePEMCertForTest(t, sec.CertChain)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	_, err = leafCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	assert.NoError(t, err, "written leaf should chain-verify against the stored CA")
}

func TestEcsDockerSecretsCmdRunDisabled(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".config", "aws-sso"), 0700))
	t.Setenv("HOME", home)
	unsetXDGConfigHomeForTest(t)

	store, err := storage.OpenJsonStore(context.Background(), filepath.Join(home, "store.json"))
	require.NoError(t, err)

	caCertPEM, caKeyPEM := genTestCA(t)
	require.NoError(t, store.SaveEcsBearerToken(context.Background(), "s3cr3t"))
	require.NoError(t, store.SaveEcsCaKeyPair(context.Background(), []byte(caKeyPEM), []byte(caCertPEM)))

	ctx := &RunContext{Store: store, Cli: &CLI{}}
	cc := &EcsDockerSecretsCmd{DisableAuth: true, DisableSSL: true}
	require.NoError(t, cc.Run(ctx))

	path := filepath.Join(home, ".config", "aws-sso", "ecs", "docker-secret.json")
	data, err := os.ReadFile(path) // nolint:gosec
	require.NoError(t, err)

	sec := &ecs.ECSSecurity{}
	require.NoError(t, json.Unmarshal(data, sec))
	assert.Empty(t, sec.BearerToken)
	assert.Empty(t, sec.PrivateKey)
	assert.Empty(t, sec.CertChain)
}

func TestEcsDockerSecretsCmdRun_ReusesStillValidLeaf(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".config", "aws-sso"), 0700))
	t.Setenv("HOME", home)
	unsetXDGConfigHomeForTest(t)

	store, err := storage.OpenJsonStore(context.Background(), filepath.Join(home, "store.json"))
	require.NoError(t, err)

	caCertPEM, caKeyPEM := genTestCA(t)
	require.NoError(t, store.SaveEcsCaKeyPair(context.Background(), []byte(caKeyPEM), []byte(caCertPEM)))

	ctx := &RunContext{Store: store, Cli: &CLI{}}
	cc := &EcsDockerSecretsCmd{DisableAuth: true}
	path := filepath.Join(home, ".config", "aws-sso", "ecs", "docker-secret.json")

	readLeaf := func() string {
		require.NoError(t, cc.Run(ctx))
		data, err := os.ReadFile(path) // nolint:gosec
		require.NoError(t, err)
		sec := &ecs.ECSSecurity{}
		require.NoError(t, json.Unmarshal(data, sec))
		return sec.CertChain
	}

	leaf1 := readLeaf()
	leaf2 := readLeaf()
	assert.Equal(t, leaf1, leaf2,
		"re-running should reuse the still-valid persisted leaf, not churn a new one")

	// ...but a leaf orphaned by a CA rotation must not be reused, even though it
	// is still well within its own validity window.
	rotatedCert, rotatedKey := genTestCA(t)
	require.NoError(t, store.SaveEcsCaKeyPair(context.Background(), []byte(rotatedKey), []byte(rotatedCert)))
	leaf3 := readLeaf()
	assert.NotEqual(t, leaf2, leaf3, "a leaf that no longer chains to the CA should be re-minted")
}

func TestEcsDockerSecretsCmdRun_MalformedCA_ReturnsError(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".config", "aws-sso"), 0700))
	t.Setenv("HOME", home)
	unsetXDGConfigHomeForTest(t)

	store, err := storage.OpenJsonStore(context.Background(), filepath.Join(home, "store.json"))
	require.NoError(t, err)

	ctx := &RunContext{Cli: &CLI{}, Store: &errStore{
		SecureStorage: store,
		getEcsCaCert:  func() (string, error) { return "not a cert", nil },
		getEcsCaKey:   func() (string, error) { return "not a key", nil },
	}}
	cc := &EcsDockerSecretsCmd{DisableAuth: true}
	err = cc.Run(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to generate leaf certificate")
}

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
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
	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	ssocache "github.com/synfinatic/aws-sso-cli/internal/sso/cache"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

// genTestCertPEM creates a throwaway ECDSA P-256 self-signed certificate/key
// pair in PEM form, valid enough to pass SaveEcsSslKeyPair's x509 validation.
func genTestCertPEM(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return
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

func TestEcsDockerWriteConfigCmdAfterApply(t *testing.T) {
	runCtx := &RunContext{}
	err := EcsDockerWriteConfigCmd{}.AfterApply(runCtx)
	require.NoError(t, err)
	assert.Equal(t, AUTH_SKIP, runCtx.Auth)
}

func TestEcsDockerWriteConfigCmdRun(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".config", "aws-sso"), 0700))
	t.Setenv("HOME", home)

	store, err := storage.OpenJsonStore(context.Background(), filepath.Join(home, "store.json"))
	require.NoError(t, err)

	certPEM, keyPEM := genTestCertPEM(t)
	require.NoError(t, store.SaveEcsBearerToken(context.Background(), "s3cr3t"))
	require.NoError(t, store.SaveEcsSslKeyPair(context.Background(), []byte(keyPEM), []byte(certPEM)))

	ctx := &RunContext{Store: store}
	cc := &EcsDockerWriteConfigCmd{}
	require.NoError(t, cc.Run(ctx))

	path := filepath.Join(home, ".aws-sso", "mnt", "docker-ecs")
	data, err := os.ReadFile(path) // nolint:gosec
	require.NoError(t, err)

	sec := &ecs.ECSSecurity{}
	require.NoError(t, json.Unmarshal(data, sec))
	assert.Equal(t, "s3cr3t", sec.BearerToken)
	assert.Equal(t, keyPEM, sec.PrivateKey)
	assert.Equal(t, certPEM, sec.CertChain)
}

func TestEcsDockerWriteConfigCmdRunDisabled(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".config", "aws-sso"), 0700))
	t.Setenv("HOME", home)

	store, err := storage.OpenJsonStore(context.Background(), filepath.Join(home, "store.json"))
	require.NoError(t, err)

	certPEM, keyPEM := genTestCertPEM(t)
	require.NoError(t, store.SaveEcsBearerToken(context.Background(), "s3cr3t"))
	require.NoError(t, store.SaveEcsSslKeyPair(context.Background(), []byte(keyPEM), []byte(certPEM)))

	ctx := &RunContext{Store: store}
	cc := &EcsDockerWriteConfigCmd{DisableAuth: true, DisableSSL: true}
	require.NoError(t, cc.Run(ctx))

	path := filepath.Join(home, ".aws-sso", "mnt", "docker-ecs")
	data, err := os.ReadFile(path) // nolint:gosec
	require.NoError(t, err)

	sec := &ecs.ECSSecurity{}
	require.NoError(t, json.Unmarshal(data, sec))
	assert.Empty(t, sec.BearerToken)
	assert.Empty(t, sec.PrivateKey)
	assert.Empty(t, sec.CertChain)
}

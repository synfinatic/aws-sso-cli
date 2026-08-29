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
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/synfinatic/aws-sso-cli/internal/certutil"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

// storeCaForTest saves a freshly generated CA directly into ctx's store,
// without going through EcsSSLCmd.Run (which would also export it to disk
// and print instructions) -- these tests only need GetEcsCaCert to return
// a real, non-empty CA cert.
func storeCaForTest(t *testing.T, ctx *RunContext) {
	t.Helper()
	ca, err := certutil.GenerateCA()
	require.NoError(t, err)
	require.NoError(t, ctx.Store.SaveEcsCaKeyPair(ctx.Ctx, []byte(ca.KeyPEM), []byte(ca.CertPEM)))
}

// errStore wraps a real SecureStorage and lets individual tests override just
// the method(s) they need to fail, falling back to the embedded store for
// everything else. This is the only way to exercise EcsSSLCmd's Store-error
// branches: the real backends essentially never fail these calls in a test
// environment.
type errStore struct {
	storage.SecureStorage
	getEcsCaCert       func() (string, error)
	getEcsCaKey        func() (string, error)
	getEcsSslCert      func() (string, error)
	deleteEcsCaKeyPair func(ctx context.Context) error
	saveEcsCaKeyPair   func(ctx context.Context, key, cert []byte) error
	saveEcsSslKeyPair  func(ctx context.Context, key, cert []byte) error
}

func (e *errStore) GetEcsCaCert() (string, error) {
	if e.getEcsCaCert != nil {
		return e.getEcsCaCert()
	}
	return e.SecureStorage.GetEcsCaCert()
}

func (e *errStore) GetEcsCaKey() (string, error) {
	if e.getEcsCaKey != nil {
		return e.getEcsCaKey()
	}
	return e.SecureStorage.GetEcsCaKey()
}

func (e *errStore) GetEcsSslCert() (string, error) {
	if e.getEcsSslCert != nil {
		return e.getEcsSslCert()
	}
	return e.SecureStorage.GetEcsSslCert()
}

func (e *errStore) DeleteEcsCaKeyPair(ctx context.Context) error {
	if e.deleteEcsCaKeyPair != nil {
		return e.deleteEcsCaKeyPair(ctx)
	}
	return e.SecureStorage.DeleteEcsCaKeyPair(ctx)
}

func (e *errStore) SaveEcsCaKeyPair(ctx context.Context, key, cert []byte) error {
	if e.saveEcsCaKeyPair != nil {
		return e.saveEcsCaKeyPair(ctx, key, cert)
	}
	return e.SecureStorage.SaveEcsCaKeyPair(ctx, key, cert)
}

func (e *errStore) SaveEcsSslKeyPair(ctx context.Context, key, cert []byte) error {
	if e.saveEcsSslKeyPair != nil {
		return e.saveEcsSslKeyPair(ctx, key, cert)
	}
	return e.SecureStorage.SaveEcsSslKeyPair(ctx, key, cert)
}

var errBoom = errors.New("boom")

func TestEcsSSLCmdRun_Delete_DeleteCaError(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Store = &errStore{
		SecureStorage:      ctx.Store,
		deleteEcsCaKeyPair: func(context.Context) error { return errBoom },
	}
	ctx.Cli.Setup.Ecs.SSL.Delete = true

	cmd := &EcsSSLCmd{}
	assert.ErrorIs(t, cmd.Run(ctx), errBoom)
}

func TestEcsSSLCmdRun_Print_GetCertError(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Store = &errStore{
		SecureStorage: ctx.Store,
		getEcsSslCert: func() (string, error) { return "", errBoom },
	}
	ctx.Cli.Setup.Ecs.SSL.Print = true

	cmd := &EcsSSLCmd{}
	assert.ErrorIs(t, cmd.Run(ctx), errBoom)
}

func TestEcsSSLCmdRun_SelfSigned_GetCaCertError(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Store = &errStore{
		SecureStorage: ctx.Store,
		getEcsCaCert:  func() (string, error) { return "", errBoom },
	}
	ctx.Cli.Setup.Ecs.SSL.SelfSigned = true

	cmd := &EcsSSLCmd{}
	assert.ErrorIs(t, cmd.Run(ctx), errBoom)
}

func TestEcsSSLCmdRun_SelfSigned_GetCaKeyError(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Store = &errStore{
		SecureStorage: ctx.Store,
		getEcsCaKey:   func() (string, error) { return "", errBoom },
	}
	ctx.Cli.Setup.Ecs.SSL.SelfSigned = true

	cmd := &EcsSSLCmd{}
	assert.ErrorIs(t, cmd.Run(ctx), errBoom)
}

func TestEcsSSLCmdRun_SelfSigned_SaveCaError(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Store = &errStore{
		SecureStorage:    ctx.Store,
		saveEcsCaKeyPair: func(context.Context, []byte, []byte) error { return errBoom },
	}
	ctx.Cli.Setup.Ecs.SSL.SelfSigned = true

	cmd := &EcsSSLCmd{}
	err := cmd.Run(ctx)
	assert.ErrorIs(t, err, errBoom)
	assert.Contains(t, err.Error(), "unable to save CA")
}

func TestEcsSSLCmdRun_SelfSigned_SaveLeafError(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Store = &errStore{
		SecureStorage:     ctx.Store,
		saveEcsSslKeyPair: func(context.Context, []byte, []byte) error { return errBoom },
	}
	ctx.Cli.Setup.Ecs.SSL.SelfSigned = true

	cmd := &EcsSSLCmd{}
	err := cmd.Run(ctx)
	assert.ErrorIs(t, err, errBoom)
	assert.Contains(t, err.Error(), "unable to save leaf certificate")
}

func TestEcsSSLCmdRun_SelfSigned_MalformedStoredCaFailsLeafGeneration(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Store = &errStore{
		SecureStorage: ctx.Store,
		getEcsCaCert:  func() (string, error) { return "not a cert", nil },
		getEcsCaKey:   func() (string, error) { return "not a key", nil },
	}
	ctx.Cli.Setup.Ecs.SSL.SelfSigned = true

	cmd := &EcsSSLCmd{}
	err := cmd.Run(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to generate leaf certificate")
}

func TestEcsSSLCmdRun_PrintCa_GetCaCertError(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Store = &errStore{
		SecureStorage: ctx.Store,
		getEcsCaCert:  func() (string, error) { return "", errBoom },
	}
	ctx.Cli.Setup.Ecs.SSL.PrintCa = true

	cmd := &EcsSSLCmd{}
	assert.ErrorIs(t, cmd.Run(ctx), errBoom)
}

func TestEcsSSLCmdRun_PrintCa_MalformedStoredCaFailsFingerprint(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Store = &errStore{
		SecureStorage: ctx.Store,
		getEcsCaCert:  func() (string, error) { return "not a cert", nil },
	}
	ctx.Cli.Setup.Ecs.SSL.PrintCa = true

	cmd := &EcsSSLCmd{}
	assert.Error(t, cmd.Run(ctx))
}

func TestEcsSSLCmdRun_PrintCa_EnsureDirExistsError(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	storeCaForTest(t, ctx)

	// The CA is exported under config.ConfigDir() (already pre-created as a
	// directory by newSelfSignedTestCtx); removing it and replacing it with a
	// regular file makes EnsureDirExists fail.
	home := os.Getenv("HOME")
	caDir := filepath.Join(home, ".config", "aws-sso")
	require.NoError(t, os.RemoveAll(caDir))                                  // nolint:gosec
	require.NoError(t, os.WriteFile(caDir, []byte("not a directory"), 0600)) // nolint:gosec

	ctx.Cli.Setup.Ecs.SSL.PrintCa = true
	cmd := &EcsSSLCmd{}
	err := cmd.Run(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exists and is not a directory")
}

func TestEcsSSLCmdRun_PrintCa_WriteFileError(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	storeCaForTest(t, ctx)

	// Pre-create the CA export path itself as a directory, so the directory
	// check/creation succeeds but writing the file to that path fails.
	home := os.Getenv("HOME")
	caPath := filepath.Join(home, ".config", "aws-sso", EcsCaExportFilename)
	require.NoError(t, os.MkdirAll(caPath, 0700)) // nolint:gosec

	ctx.Cli.Setup.Ecs.SSL.PrintCa = true
	cmd := &EcsSSLCmd{}
	err := cmd.Run(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to write")
}

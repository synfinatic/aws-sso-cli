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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/synfinatic/aws-sso-cli/internal/certutil"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

// storeCaForTest saves a freshly generated CA directly into ctx's store,
// without going through EcsSSLCmd.Run (which would also print to stdout)
// -- these tests only need GetEcsCaCert to return a real, non-empty CA cert.
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
	getEcsBearerToken  func() (string, error)
	deleteEcsCaKeyPair func(ctx context.Context) error
	saveEcsCaKeyPair   func(ctx context.Context, key, cert []byte) error
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

func (e *errStore) GetEcsBearerToken() (string, error) {
	if e.getEcsBearerToken != nil {
		return e.getEcsBearerToken()
	}
	return e.SecureStorage.GetEcsBearerToken()
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

// --print-ca no longer parses the CA at all (it just streams the stored PEM), so
// the fingerprint failure path now belongs to --self-signed, which reuses the
// stored CA without regenerating it and then fingerprints it for its summary.
func TestEcsSSLCmdRun_SelfSigned_MalformedStoredCaFailsFingerprint(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Store = &errStore{
		SecureStorage: ctx.Store,
		getEcsCaCert:  func() (string, error) { return "not a cert", nil },
	}
	ctx.Cli.Setup.Ecs.SSL.SelfSigned = true

	cmd := &EcsSSLCmd{}
	assert.Error(t, cmd.Run(ctx))
}

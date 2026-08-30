package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

func openTestStore(t *testing.T) storage.SecureStorage {
	t.Helper()
	ctx := context.Background()
	store, err := storage.OpenJsonStore(ctx, filepath.Join(t.TempDir(), "store.json"))
	require.NoError(t, err)
	return store
}

func TestEcsSSLCmdAfterApply(t *testing.T) {
	ctx := &RunContext{Cli: &CLI{}}
	cmd := EcsSSLCmd{}
	require.NoError(t, cmd.AfterApply(ctx))
	assert.Equal(t, AUTH_SKIP, ctx.Auth)
}

func TestEcsSSLCmdRun_Delete(t *testing.T) {
	store := openTestStore(t)
	ctx := &RunContext{
		Cli:   &CLI{},
		Store: store,
		Ctx:   context.Background(),
	}
	ctx.Cli.Setup.Ecs.SSL.Delete = true

	cmd := &EcsSSLCmd{}
	// Store is empty; DeleteEcsCaKeyPair on an empty store still returns nil.
	assert.NoError(t, cmd.Run(ctx))
}

func newSelfSignedTestCtx(t *testing.T) *RunContext {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	// FlockFile() derives its path from config.ConfigDir(), which in turn
	// resolves against $HOME; the lock file's parent directory must exist
	// before any SecureStorage Save*/Delete* call runs.
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".config", "aws-sso"), 0700))
	store := openTestStore(t)
	return &RunContext{
		Cli:   &CLI{},
		Store: store,
		Ctx:   context.Background(),
	}
}

func parsePEMCertForTest(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func TestEcsSSLCmdRun_SelfSigned_FreshCA(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Cli.Setup.Ecs.SSL.SelfSigned = true

	cmd := &EcsSSLCmd{}
	require.NoError(t, cmd.Run(ctx))

	caCert, err := ctx.Store.GetEcsCaCert()
	require.NoError(t, err)
	caKey, err := ctx.Store.GetEcsCaKey()
	require.NoError(t, err)
	assert.NotEmpty(t, caCert)
	assert.NotEmpty(t, caKey)
}

func TestEcsSSLCmdRun_SelfSigned_RerunReusesCA(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Cli.Setup.Ecs.SSL.SelfSigned = true

	cmd := &EcsSSLCmd{}
	require.NoError(t, cmd.Run(ctx))

	caCert1, err := ctx.Store.GetEcsCaCert()
	require.NoError(t, err)

	require.NoError(t, cmd.Run(ctx))

	caCert2, err := ctx.Store.GetEcsCaCert()
	require.NoError(t, err)

	assert.Equal(t, caCert1, caCert2, "CA must be byte-for-byte identical across reruns")
}

// TestEcsSSLCmdRun_SelfSigned_ReuseNeverReadsCaKey confirms the reuse path
// (--self-signed, CA already present, no --rotate-ca) no longer mints a leaf
// and so never needs the CA private key -- only GetEcsCaCert is consulted.
func TestEcsSSLCmdRun_SelfSigned_ReuseNeverReadsCaKey(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	storeCaForTest(t, ctx)

	ctx.Store = &errStore{
		SecureStorage: ctx.Store,
		getEcsCaKey: func() (string, error) {
			t.Fatal("GetEcsCaKey should not be called when reusing an existing CA")
			return "", nil
		},
	}
	ctx.Cli.Setup.Ecs.SSL.SelfSigned = true

	cmd := &EcsSSLCmd{}
	require.NoError(t, cmd.Run(ctx))
}

func TestEcsSSLCmdRun_SelfSigned_RotateCa(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Cli.Setup.Ecs.SSL.SelfSigned = true

	cmd := &EcsSSLCmd{}
	require.NoError(t, cmd.Run(ctx))

	caCert1, err := ctx.Store.GetEcsCaCert()
	require.NoError(t, err)

	ctx.Cli.Setup.Ecs.SSL.RotateCa = true
	require.NoError(t, cmd.Run(ctx))

	caCert2, err := ctx.Store.GetEcsCaCert()
	require.NoError(t, err)

	assert.NotEqual(t, caCert1, caCert2, "--rotate-ca should generate a brand new CA")
}

func TestEcsSSLCmdRun_Delete_ClearsCa(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Cli.Setup.Ecs.SSL.SelfSigned = true

	cmd := &EcsSSLCmd{}
	require.NoError(t, cmd.Run(ctx))

	ctx.Cli.Setup.Ecs.SSL.SelfSigned = false
	ctx.Cli.Setup.Ecs.SSL.Delete = true
	require.NoError(t, cmd.Run(ctx))

	caCert, err := ctx.Store.GetEcsCaCert()
	require.NoError(t, err)
	assert.Empty(t, caCert)
}

func TestEcsSSLCmdRun_PrintCa_NoCa(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Cli.Setup.Ecs.SSL.PrintCa = true

	cmd := &EcsSSLCmd{}
	err := cmd.Run(ctx)
	assert.Error(t, err)
}

func TestEcsSSLCmdRun_PrintCa_AfterSelfSigned(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Cli.Setup.Ecs.SSL.SelfSigned = true

	cmd := &EcsSSLCmd{}
	require.NoError(t, cmd.Run(ctx))

	ctx.Cli.Setup.Ecs.SSL.SelfSigned = false
	ctx.Cli.Setup.Ecs.SSL.PrintCa = true
	assert.NoError(t, cmd.Run(ctx))
}

func TestEcsAuthCmdAfterApply(t *testing.T) {
	ctx := &RunContext{Cli: &CLI{}}
	cmd := EcsAuthCmd{}
	require.NoError(t, cmd.AfterApply(ctx))
	assert.Equal(t, AUTH_SKIP, ctx.Auth)
}

func TestEcsAuthCmdRun_NoBearerToken(t *testing.T) {
	store := openTestStore(t)
	ctx := &RunContext{
		Cli:   &CLI{},
		Store: store,
		Ctx:   context.Background(),
	}
	// BearerToken is empty, Delete is false → should return an error.
	cmd := &EcsAuthCmd{}
	err := cmd.Run(ctx)
	assert.Error(t, err)
}

func TestEcsAuthCmdRun_SaveBearerToken(t *testing.T) {
	store := openTestStore(t)
	ctx := &RunContext{
		Cli:   &CLI{},
		Store: store,
		Ctx:   context.Background(),
	}
	ctx.Cli.Setup.Ecs.Auth.BearerToken = "my-secret-token"

	cmd := &EcsAuthCmd{}
	assert.NoError(t, cmd.Run(ctx))
}

func TestEcsAuthCmdRun_BearerTokenWithPrefix(t *testing.T) {
	store := openTestStore(t)
	ctx := &RunContext{
		Cli:   &CLI{},
		Store: store,
		Ctx:   context.Background(),
	}
	ctx.Cli.Setup.Ecs.Auth.BearerToken = "Bearer already-prefixed"

	cmd := &EcsAuthCmd{}
	err := cmd.Run(ctx)
	assert.Error(t, err)
}

func TestEcsAuthCmdRun_Delete(t *testing.T) {
	store := openTestStore(t)
	ctx := &RunContext{
		Cli:   &CLI{},
		Store: store,
		Ctx:   context.Background(),
	}
	ctx.Cli.Setup.Ecs.Auth.Delete = true

	cmd := &EcsAuthCmd{}
	// Nothing stored to delete; should return nil.
	assert.NoError(t, cmd.Run(ctx))
}

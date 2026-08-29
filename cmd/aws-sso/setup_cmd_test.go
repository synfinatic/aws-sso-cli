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
	// Store is empty; DeleteEcsSslKeyPair on an empty store still returns nil.
	assert.NoError(t, cmd.Run(ctx))
}

func TestEcsSSLCmdRun_Print_NoCert(t *testing.T) {
	store := openTestStore(t)
	ctx := &RunContext{
		Cli:   &CLI{},
		Store: store,
		Ctx:   context.Background(),
	}
	ctx.Cli.Setup.Ecs.SSL.Print = true

	cmd := &EcsSSLCmd{}
	// No certificate stored; Run should return an error.
	err := cmd.Run(ctx)
	assert.Error(t, err)
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

	leafCert, err := ctx.Store.GetEcsSslCert()
	require.NoError(t, err)
	leafKey, err := ctx.Store.GetEcsSslKey()
	require.NoError(t, err)
	assert.NotEmpty(t, leafCert)
	assert.NotEmpty(t, leafKey)

	pool := x509.NewCertPool()
	pool.AddCert(parsePEMCertForTest(t, caCert))
	_, err = parsePEMCertForTest(t, leafCert).Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	assert.NoError(t, err, "leaf certificate should chain-verify against the generated CA")
}

func TestEcsSSLCmdRun_SelfSigned_RerunReusesCA(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Cli.Setup.Ecs.SSL.SelfSigned = true

	cmd := &EcsSSLCmd{}
	require.NoError(t, cmd.Run(ctx))

	caCert1, err := ctx.Store.GetEcsCaCert()
	require.NoError(t, err)
	leafCert1, err := ctx.Store.GetEcsSslCert()
	require.NoError(t, err)

	require.NoError(t, cmd.Run(ctx))

	caCert2, err := ctx.Store.GetEcsCaCert()
	require.NoError(t, err)
	leafCert2, err := ctx.Store.GetEcsSslCert()
	require.NoError(t, err)

	assert.Equal(t, caCert1, caCert2, "CA must be byte-for-byte identical across reruns")
	assert.NotEqual(t, leafCert1, leafCert2, "leaf certificate should rotate on rerun")
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

func TestEcsSSLCmdRun_SelfSigned_San(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Cli.Setup.Ecs.SSL.SelfSigned = true
	ctx.Cli.Setup.Ecs.SSL.San = []string{"myhost.example.com", "10.1.2.3"}

	cmd := &EcsSSLCmd{}
	require.NoError(t, cmd.Run(ctx))

	leafCert, err := ctx.Store.GetEcsSslCert()
	require.NoError(t, err)
	cert := parsePEMCertForTest(t, leafCert)

	assert.Contains(t, cert.DNSNames, "myhost.example.com")

	ips := make([]string, len(cert.IPAddresses))
	for i, ip := range cert.IPAddresses {
		ips[i] = ip.String()
	}
	assert.Contains(t, ips, "10.1.2.3")
}

func TestEcsSSLCmdRun_Delete_ClearsCaAndLeaf(t *testing.T) {
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

	leafCert, err := ctx.Store.GetEcsSslCert()
	require.NoError(t, err)
	assert.Empty(t, leafCert)
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

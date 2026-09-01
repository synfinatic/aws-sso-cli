package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/synfinatic/aws-sso-cli/internal/certutil"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

// errStore wraps a real SecureStorage and lets tests force a specific method
// to fail, without having to hand-implement the entire SecureStorage
// interface just to exercise a handful of error-return branches.
type errStore struct {
	storage.SecureStorage
	getEcsSslCertErr       error
	getEcsCaCertErr        error
	getEcsCaKeyErr         error
	saveEcsCaKeyPairErr    error
	saveEcsSslKeyPairErr   error
	deleteEcsSslKeyPairErr error
}

func (e *errStore) GetEcsSslCert() (string, error) {
	if e.getEcsSslCertErr != nil {
		return "", e.getEcsSslCertErr
	}
	return e.SecureStorage.GetEcsSslCert()
}

func (e *errStore) GetEcsCaCert() (string, error) {
	if e.getEcsCaCertErr != nil {
		return "", e.getEcsCaCertErr
	}
	return e.SecureStorage.GetEcsCaCert()
}

func (e *errStore) GetEcsCaKey() (string, error) {
	if e.getEcsCaKeyErr != nil {
		return "", e.getEcsCaKeyErr
	}
	return e.SecureStorage.GetEcsCaKey()
}

func (e *errStore) SaveEcsCaKeyPair(ctx context.Context, key, cert []byte) error {
	if e.saveEcsCaKeyPairErr != nil {
		return e.saveEcsCaKeyPairErr
	}
	return e.SecureStorage.SaveEcsCaKeyPair(ctx, key, cert)
}

func (e *errStore) SaveEcsSslKeyPair(ctx context.Context, key, cert []byte) error {
	if e.saveEcsSslKeyPairErr != nil {
		return e.saveEcsSslKeyPairErr
	}
	return e.SecureStorage.SaveEcsSslKeyPair(ctx, key, cert)
}

func (e *errStore) DeleteEcsSslKeyPair(ctx context.Context) error {
	if e.deleteEcsSslKeyPairErr != nil {
		return e.deleteEcsSslKeyPairErr
	}
	return e.SecureStorage.DeleteEcsSslKeyPair(ctx)
}

// captureTestStdout runs fn with os.Stdout redirected and returns everything
// written to it, restoring os.Stdout afterward even if fn panics.
func captureTestStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	old := os.Stdout
	os.Stdout = w

	func() {
		defer func() {
			w.Close()
			os.Stdout = old
		}()
		fn()
	}()

	var buf bytes.Buffer
	_, err = buf.ReadFrom(r)
	require.NoError(t, err)
	return buf.String()
}

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

func TestEcsSSLCmdRun_NoFlagSet(t *testing.T) {
	store := openTestStore(t)
	ctx := &RunContext{
		Cli:   &CLI{},
		Store: store,
		Ctx:   context.Background(),
	}

	cmd := &EcsSSLCmd{}
	err := cmd.Run(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must specify one of --delete, --print-ca, or --self-signed")
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

func TestEcsSSLCmdRun_PrintCa_OutputsOnlyPEM(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Cli.Setup.Ecs.SSL.SelfSigned = true

	cmd := &EcsSSLCmd{}
	require.NoError(t, cmd.Run(ctx))

	caCert, err := ctx.Store.GetEcsCaCert()
	require.NoError(t, err)

	ctx.Cli.Setup.Ecs.SSL.SelfSigned = false
	ctx.Cli.Setup.Ecs.SSL.PrintCa = true

	var runErr error
	output := captureTestStdout(t, func() {
		runErr = cmd.Run(ctx)
	})
	require.NoError(t, runErr)

	assert.Equal(t, strings.TrimSpace(caCert), strings.TrimSpace(output),
		"--print-ca should print only the CA certificate PEM, nothing else")
}

func TestEcsSSLCmdRun_SelfSigned_PrintsDocsURL(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Cli.Setup.Ecs.SSL.SelfSigned = true

	cmd := &EcsSSLCmd{}
	var runErr error
	output := captureTestStdout(t, func() {
		runErr = cmd.Run(ctx)
	})
	require.NoError(t, runErr)

	assert.Contains(t, output, EcsCaTrustDocsURL,
		"--self-signed should point the user at the docs instead of printing instructions inline")
	assert.NotContains(t, output, "== macOS ==",
		"--self-signed should no longer print inline per-OS trust instructions")
}

func TestEcsSSLCmdRun_Delete_DeleteSslKeyPairError(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Store = &errStore{SecureStorage: ctx.Store, deleteEcsSslKeyPairErr: errors.New("boom")}
	ctx.Cli.Setup.Ecs.SSL.Delete = true

	err := (&EcsSSLCmd{}).Run(ctx)
	assert.ErrorContains(t, err, "boom")
}

func TestEcsSSLCmdRun_PrintCa_GetCaCertError(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Store = &errStore{SecureStorage: ctx.Store, getEcsCaCertErr: errors.New("boom")}
	ctx.Cli.Setup.Ecs.SSL.PrintCa = true

	err := (&EcsSSLCmd{}).Run(ctx)
	assert.ErrorContains(t, err, "boom")
}

func TestEcsSSLCmdRun_SelfSigned_GetCaCertError(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Store = &errStore{SecureStorage: ctx.Store, getEcsCaCertErr: errors.New("boom")}
	ctx.Cli.Setup.Ecs.SSL.SelfSigned = true

	err := (&EcsSSLCmd{}).Run(ctx)
	assert.ErrorContains(t, err, "boom")
}

func TestEcsSSLCmdRun_SelfSigned_GetCaKeyError(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Store = &errStore{SecureStorage: ctx.Store, getEcsCaKeyErr: errors.New("boom")}
	ctx.Cli.Setup.Ecs.SSL.SelfSigned = true

	err := (&EcsSSLCmd{}).Run(ctx)
	assert.ErrorContains(t, err, "boom")
}

func TestEcsSSLCmdRun_SelfSigned_SaveCaKeyPairError(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Store = &errStore{SecureStorage: ctx.Store, saveEcsCaKeyPairErr: errors.New("boom")}
	ctx.Cli.Setup.Ecs.SSL.SelfSigned = true

	err := (&EcsSSLCmd{}).Run(ctx)
	assert.ErrorContains(t, err, "unable to save CA")
}

func TestEcsSSLCmdRun_SelfSigned_SaveSslKeyPairError(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	ctx.Store = &errStore{SecureStorage: ctx.Store, saveEcsSslKeyPairErr: errors.New("boom")}
	ctx.Cli.Setup.Ecs.SSL.SelfSigned = true

	err := (&EcsSSLCmd{}).Run(ctx)
	assert.ErrorContains(t, err, "unable to save leaf certificate")
}

func TestEcsSSLCmdRun_SelfSigned_GenerateLeafError(t *testing.T) {
	ctx := newSelfSignedTestCtx(t)
	// Pre-seed a CA that loadOrGenerateCa will happily reuse (both fields
	// non-empty, and each individually valid enough to pass the store's own
	// PEM validation) but paired together are not a usable CA: an RSA key
	// can't sign as the ECDSA key certutil expects, forcing the
	// GenerateLeaf error branch in runSelfSigned.
	ca, err := certutil.GenerateCA()
	require.NoError(t, err)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaKeyDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	rsaKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaKeyDER})

	require.NoError(t, ctx.Store.SaveEcsCaKeyPair(ctx.Ctx, rsaKeyPEM, []byte(ca.CertPEM)))
	ctx.Cli.Setup.Ecs.SSL.SelfSigned = true

	err = (&EcsSSLCmd{}).Run(ctx)
	assert.ErrorContains(t, err, "unable to generate leaf certificate")
}

func TestEcsSSLCmdRun_SelfSigned_DoesNotWriteCaFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".config", "aws-sso"), 0700))
	store := openTestStore(t)
	ctx := &RunContext{
		Cli:   &CLI{},
		Store: store,
		Ctx:   context.Background(),
	}
	ctx.Cli.Setup.Ecs.SSL.SelfSigned = true

	require.NoError(t, (&EcsSSLCmd{}).Run(ctx))

	_, err := os.Stat(filepath.Join(home, ".aws-sso", "ecs-ca.pem"))
	assert.True(t, os.IsNotExist(err), "--self-signed must not write the CA certificate to disk")
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

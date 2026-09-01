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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/synfinatic/aws-sso-cli/internal/certutil"
	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	"github.com/synfinatic/aws-sso-cli/internal/ecs/client"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	testlogger "github.com/synfinatic/flexlog/test"
)

// newDockerPersistTestCtx isolates $HOME, stores a throwaway CA and bearer
// token, and returns a RunContext plus the host paths the ECS security and
// bearer-token files resolve to under that $HOME.
func newDockerPersistTestCtx(t *testing.T) (ctx *RunContext, secPath, tokenPath string) {
	t.Helper()
	return newDockerPersistTestCtxIn(t, "")
}

// newDockerPersistTestCtxIn is newDockerPersistTestCtx with an explicit
// --secrets-dir; an empty secretsDir means the default config-dir location.
func newDockerPersistTestCtxIn(t *testing.T, secretsDir string) (ctx *RunContext, secPath, tokenPath string) {
	t.Helper()

	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".config", "aws-sso"), 0700))
	t.Setenv("HOME", home)
	// config.ConfigDir() prefers a real, un-isolated XDG_CONFIG_HOME (e.g. on
	// CI runners that export one) over the $HOME override above.
	unsetXDGConfigHomeForTest(t)

	store, err := storage.OpenJsonStore(context.Background(), filepath.Join(home, "store.json"))
	require.NoError(t, err)

	caCertPEM, caKeyPEM := genTestCA(t)
	require.NoError(t, store.SaveEcsBearerToken(context.Background(), "s3cr3t"))
	require.NoError(t, store.SaveEcsCaKeyPair(context.Background(), []byte(caKeyPEM), []byte(caCertPEM)))

	// Cli is non-nil because the commands under test read
	// ctx.Cli.Ecs.SecretsDir, the same way EcsLoadCmd.Run reads
	// ctx.Cli.Ecs.Load.Arn
	ctx = &RunContext{Store: store, Cli: &CLI{}}
	ctx.Cli.Ecs.SecretsDir = secretsDir

	ecsDir := secretsDir
	if ecsDir == "" {
		ecsDir = filepath.Join(home, ".config", "aws-sso", "ecs")
	}
	return ctx,
		filepath.Join(ecsDir, "docker-secret.json"),
		filepath.Join(ecsDir, "bearer-token")
}

func readSecurityFileForTest(t *testing.T, path string) *ecs.ECSSecurity {
	t.Helper()
	data, err := os.ReadFile(path) // nolint:gosec
	require.NoError(t, err)
	sec := &ecs.ECSSecurity{}
	require.NoError(t, json.Unmarshal(data, sec))
	return sec
}

func writeSecurityFileForTest(t *testing.T, path string, sec ecs.ECSSecurity) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
	data, err := json.Marshal(&sec)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0600))
}

// TestEcsDockerSecretsEmitsBearerTokenFile covers the companion file that client
// containers mount for AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE.  The AWS SDKs
// send the file's bytes verbatim as the Authorization header, so the "Bearer "
// prefix has to be in the file and there must be no trailing newline.
func TestEcsDockerSecretsEmitsBearerTokenFile(t *testing.T) {
	ctx, _, tokenPath := newDockerPersistTestCtx(t)

	cc := &EcsDockerSecretsCmd{}
	require.NoError(t, cc.Run(ctx))

	data, err := os.ReadFile(tokenPath) // nolint:gosec
	require.NoError(t, err)
	assert.Equal(t, "Bearer s3cr3t", string(data))

	fi, err := os.Stat(tokenPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), fi.Mode().Perm())
}

// TestEcsDockerSecretsDisableAuthRemovesBearerTokenFile confirms --disable-auth does
// not leave a previously written token behind.
func TestEcsDockerSecretsDisableAuthRemovesBearerTokenFile(t *testing.T) {
	ctx, _, tokenPath := newDockerPersistTestCtx(t)

	require.NoError(t, (&EcsDockerSecretsCmd{}).Run(ctx))
	require.FileExists(t, tokenPath)

	require.NoError(t, (&EcsDockerSecretsCmd{DisableAuth: true}).Run(ctx))
	assert.NoFileExists(t, tokenPath)
}

// TestEcsDockerSecretsRemovesLegacySecurityFile confirms the pre-XDG file is cleaned
// up rather than left on disk as a stale plaintext copy of the bearer token and
// SSL private key.
func TestEcsDockerSecretsRemovesLegacySecurityFile(t *testing.T) {
	ctx, _, _ := newDockerPersistTestCtx(t)

	home := os.Getenv("HOME")
	legacyDir := filepath.Join(home, ".aws-sso", "mnt")
	legacyFile := filepath.Join(legacyDir, "docker-ecs")
	require.NoError(t, os.MkdirAll(legacyDir, 0700))                                    // nolint:gosec
	require.NoError(t, os.WriteFile(legacyFile, []byte(`{"bearerToken":"old"}`), 0600)) // nolint:gosec

	require.NoError(t, (&EcsDockerSecretsCmd{}).Run(ctx))

	assert.NoFileExists(t, legacyFile)
	assert.NoDirExists(t, legacyDir, "the now-empty legacy directory should go too")
}

// TestRefreshDockerSecurityFileIfStale_NoFile is the case that matters for
// everyone not running the ECS Server in Docker: the refresh hook runs on
// `ecs load`/`list`/`profile` and must never bring the file into existence.
func TestRefreshDockerSecurityFileIfStale_NoFile(t *testing.T) {
	ctx, secPath, _ := newDockerPersistTestCtx(t)

	refreshDockerSecurityFileIfStale(ctx)
	assert.NoFileExists(t, secPath)
}

// TestRefreshDockerSecurityFileIfStale_NilStore guards the AUTH_NO_CONFIG
// commands, which return before loadSecureStore runs and so have no CA to mint
// from.
func TestRefreshDockerSecurityFileIfStale_NilStore(t *testing.T) {
	_, secPath, _ := newDockerPersistTestCtx(t)

	writeSecurityFileForTest(t, secPath, ecs.ECSSecurity{
		PrivateKey:  "key",
		CertChain:   genTestCertWithNotAfter(t, time.Now().Add(time.Hour)),
		BearerToken: "s3cr3t",
	})
	before := readSecurityFileForTest(t, secPath)

	refreshDockerSecurityFileIfStale(&RunContext{})
	assert.Equal(t, before, readSecurityFileForTest(t, secPath))
}

// TestRefreshDockerSecurityFileIfStale_FreshLeafUntouched: rewriting the file on
// every `ecs load` would invalidate what a running container is already serving,
// so a leaf with plenty of life left must be left exactly as-is.
func TestRefreshDockerSecurityFileIfStale_FreshLeafUntouched(t *testing.T) {
	ctx, secPath, _ := newDockerPersistTestCtx(t)

	require.NoError(t, (&EcsDockerSecretsCmd{}).Run(ctx))
	before := readSecurityFileForTest(t, secPath)

	refreshDockerSecurityFileIfStale(ctx)
	assert.Equal(t, before, readSecurityFileForTest(t, secPath))
}

// TestRefreshDockerSecurityFileIfStale_StaleLeafReminted is the whole point of
// the hook: an aging persisted leaf gets topped up from the stored CA, and the
// bearer token -- which the hook has no business changing -- survives intact.
func TestRefreshDockerSecurityFileIfStale_StaleLeafReminted(t *testing.T) {
	ctx, secPath, _ := newDockerPersistTestCtx(t)

	stale := genTestCertWithNotAfter(t, time.Now().Add(leafRefreshThreshold-time.Hour))
	writeSecurityFileForTest(t, secPath, ecs.ECSSecurity{
		PrivateKey:  "stale-key",
		CertChain:   stale,
		BearerToken: "s3cr3t",
	})

	refreshDockerSecurityFileIfStale(ctx)

	after := readSecurityFileForTest(t, secPath)
	assert.NotEqual(t, stale, after.CertChain, "a stale leaf should be re-minted")
	assert.NotEqual(t, "stale-key", after.PrivateKey)
	assert.Equal(t, "s3cr3t", after.BearerToken, "the bearer token must be preserved")

	caCert, err := ctx.Store.GetEcsCaCert()
	require.NoError(t, err)
	assert.NoError(t, certutil.VerifyLeafAgainstCA(after.CertChain, caCert),
		"the refreshed leaf should chain to the stored CA")
}

// TestRefreshDockerSecurityFileIfStale_NoSSLMaterial: a file written with
// --disable-ssl has no leaf to refresh, and the hook must not quietly turn SSL
// back on behind the user's back.
func TestRefreshDockerSecurityFileIfStale_NoSSLMaterial(t *testing.T) {
	ctx, secPath, _ := newDockerPersistTestCtx(t)

	require.NoError(t, (&EcsDockerSecretsCmd{DisableSSL: true}).Run(ctx))
	before := readSecurityFileForTest(t, secPath)
	require.Empty(t, before.CertChain)
	assert.True(t, before.DisableSSL, "the flag was passed, so the file must record it as intentional")

	refreshDockerSecurityFileIfStale(ctx)
	assert.Equal(t, before, readSecurityFileForTest(t, secPath))
}

// TestEcsDockerSecretsCmdRun_NoCARecordsUnintentional: no CA configured and
// --disable-ssl not passed must not be recorded the same way as an explicit
// opt-out -- ecs server --docker relies on this bit to fail closed here and
// start open on a genuine --disable-ssl file.
func TestEcsDockerSecretsCmdRun_NoCARecordsUnintentional(t *testing.T) {
	tLogger := testlogger.NewTestLogger("DEBUG")
	defer tLogger.Close()
	oldLog := log
	log = tLogger
	defer func() { log = oldLog }()

	ctx := newSelfSignedTestCtx(t)
	secPath := filepath.Join(ecs.HostMountPoint(""), "docker-secret.json")

	require.NoError(t, (&EcsDockerSecretsCmd{}).Run(ctx))

	sec := readSecurityFileForTest(t, secPath)
	assert.Empty(t, sec.CertChain)
	assert.False(t, sec.DisableSSL, "the flag was not passed, so this must not read as intentional")
	assert.Empty(t, sec.BearerToken)
	assert.False(t, sec.DisableAuth, "the flag was not passed, so this must not read as intentional")

	var messages []string
	for {
		msg := testlogger.LogMessage{}
		if err := tLogger.GetNext(&msg); err != nil {
			break
		}
		messages = append(messages, msg.Message)
	}
	assert.Contains(t, messages, "No CA found in the SecureStore, and --disable-ssl was not passed: "+
		"the ECS Server will refuse to start until you either run "+
		"`aws-sso setup ecs ssl --self-signed`, or pass --disable-ssl here to record that no TLS is intentional.")
	assert.Contains(t, messages, "No bearer token configured, and --disable-auth was not passed: "+
		"the ECS Server will refuse to start until you either run "+
		"`aws-sso setup ecs auth`, or pass --disable-auth here to record that no HTTP Auth is intentional.")
}

// TestEcsDockerSecretsCmdRun_DisableFlagsRecordIntentional is the flip side:
// passing --disable-ssl/--disable-auth must set the corresponding bit and
// must not warn, since the empty fields are exactly what was asked for.
func TestEcsDockerSecretsCmdRun_DisableFlagsRecordIntentional(t *testing.T) {
	tLogger := testlogger.NewTestLogger("DEBUG")
	defer tLogger.Close()
	oldLog := log
	log = tLogger
	defer func() { log = oldLog }()

	ctx, secPath, _ := newDockerPersistTestCtx(t)

	require.NoError(t, (&EcsDockerSecretsCmd{DisableSSL: true, DisableAuth: true}).Run(ctx))

	sec := readSecurityFileForTest(t, secPath)
	assert.True(t, sec.DisableSSL)
	assert.True(t, sec.DisableAuth)

	var messages []string
	for {
		msg := testlogger.LogMessage{}
		if err := tLogger.GetNext(&msg); err != nil {
			break
		}
		messages = append(messages, msg.Message)
	}
	for _, m := range messages {
		assert.NotContains(t, m, "will refuse to start",
			"an explicit --disable-ssl/--disable-auth needs no warning")
	}
}

// TestRefreshDockerSecurityFileIfStale_Unparseable: background maintenance must
// never destroy a file it cannot understand, and never fail the command it is
// piggybacking on.
func TestRefreshDockerSecurityFileIfStale_Unparseable(t *testing.T) {
	ctx, secPath, _ := newDockerPersistTestCtx(t)

	require.NoError(t, os.MkdirAll(filepath.Dir(secPath), 0700))
	require.NoError(t, os.WriteFile(secPath, []byte("not json"), 0600))

	refreshDockerSecurityFileIfStale(ctx)

	data, err := os.ReadFile(secPath) // nolint:gosec
	require.NoError(t, err)
	assert.Equal(t, "not json", string(data))
}

// TestRefreshDockerSecurityFileIfStale_UnparseableCert covers a well-formed JSON
// file whose certChain is garbage: same rule, leave it alone.
func TestRefreshDockerSecurityFileIfStale_UnparseableCert(t *testing.T) {
	ctx, secPath, _ := newDockerPersistTestCtx(t)

	writeSecurityFileForTest(t, secPath, ecs.ECSSecurity{
		PrivateKey:  "key",
		CertChain:   "not a cert",
		BearerToken: "s3cr3t",
	})
	before := readSecurityFileForTest(t, secPath)

	refreshDockerSecurityFileIfStale(ctx)
	assert.Equal(t, before, readSecurityFileForTest(t, secPath))
}

// TestEcsServerCmdRun_DockerFailsClosed is the regression this whole change
// exists for.  With a missing security config the server used to log a warning
// and start anyway -- serving AWS credentials with no HTTP Auth and no TLS.
// A missing file is now unconditionally fatal: Docker mode no longer reads its
// own --disable-auth/--disable-ssl CLI flags at all, so there is no flag
// combination that lets a missing file start an open server -- the security
// file, written by `ecs docker secrets`, is the only way to ask for that.
func TestEcsServerCmdRun_DockerFailsClosed(t *testing.T) {
	tests := []struct {
		name        string
		disableAuth bool
		disableSSL  bool
	}{
		{name: "neither CLI flag set"},
		{name: "--disable-auth set (ignored under --docker)", disableAuth: true},
		{name: "--disable-ssl set (ignored under --docker)", disableSSL: true},
		{name: "both CLI flags set (still ignored -- file is the source of truth)", disableAuth: true, disableSSL: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, _, _ := newDockerPersistTestCtx(t)
			ctx.Cli = &CLI{}
			ctx.Cli.Ecs.Server = EcsServerCmd{
				BindIP:      "127.0.0.1",
				Port:        freeTestPort(t),
				Docker:      true,
				DisableAuth: tt.disableAuth,
				DisableSSL:  tt.disableSSL,
			}
			cc := &ctx.Cli.Ecs.Server

			err := cc.Run(ctx)
			require.Error(t, err, "a missing security config must not start an open server")
			assert.Contains(t, err.Error(), "unable to read the ECS security config")
			assert.Contains(t, err.Error(), "aws-sso ecs docker secrets",
				"the error should name the command that fixes it")
		})
	}
}

// TestEcsServerCmdRun_DockerBothDisabledStartsOpen confirms the deliberate
// opt-out still works: asking for no auth and no TLS needs a security file
// that records both bits, written by `ecs docker secrets --disable-auth
// --disable-ssl` -- the CLI flags on `ecs server` itself are no longer read
// under --docker.
func TestEcsServerCmdRun_DockerBothDisabledStartsOpen(t *testing.T) {
	ctx, secPath, _ := newDockerPersistTestCtx(t)
	ctx.Cli = &CLI{}

	require.NoError(t, (&EcsDockerSecretsCmd{DisableAuth: true, DisableSSL: true}).Run(ctx))
	// the container reads from a path baked into the image; point it at the
	// host file this command just wrote, as the bind mount would in production
	ecs.TestContainerFilePathOverride = secPath
	t.Cleanup(func() { ecs.TestContainerFilePathOverride = "" })

	cctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ctx.Ctx = cctx

	port := freeTestPort(t)
	ctx.Cli.Ecs.Server = EcsServerCmd{
		BindIP: "127.0.0.1",
		Port:   port,
		Docker: true,
	}
	cc := &ctx.Cli.Ecs.Server

	done := make(chan error, 1)
	go func() { done <- cc.Run(ctx) }()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	require.NoError(t, waitForEcsServerUp("http", addr, "", 5*time.Second))

	cancel()
	assert.NoError(t, <-done)
}

// TestEcsServerCmdRun_DockerUnexplainedEmptySSLFailsClosed is the direct
// regression test for the file-present-but-empty case: a security file with no
// SSL material and DisableSSL not set must not start an open server just
// because the file could be read.
func TestEcsServerCmdRun_DockerUnexplainedEmptySSLFailsClosed(t *testing.T) {
	ctx, _, _ := newDockerPersistTestCtx(t)
	writeDockerSecurityFileForTest(t, ecs.ECSSecurity{
		BearerToken: "s3cr3t",
	})

	ctx.Cli = &CLI{}
	ctx.Ctx = context.Background()
	ctx.Cli.Ecs.Server = EcsServerCmd{BindIP: "127.0.0.1", Port: freeTestPort(t), Docker: true}

	err := ctx.Cli.Ecs.Server.Run(ctx)
	require.Error(t, err, "empty SSL material with DisableSSL unset must fail closed")
	assert.Contains(t, err.Error(), "--disable-ssl")
}

// TestEcsServerCmdRun_DockerUnexplainedEmptyAuthFailsClosed is the Auth
// counterpart: an empty bearer token with DisableAuth not set must not start
// an open server.
func TestEcsServerCmdRun_DockerUnexplainedEmptyAuthFailsClosed(t *testing.T) {
	ctx, _, _ := newDockerPersistTestCtx(t)

	caCert, err := ctx.Store.GetEcsCaCert()
	require.NoError(t, err)
	caKey, err := ctx.Store.GetEcsCaKey()
	require.NoError(t, err)
	leaf, err := certutil.GenerateLeaf(certutil.KeyPair{CertPEM: caCert, KeyPEM: caKey})
	require.NoError(t, err)

	writeDockerSecurityFileForTest(t, ecs.ECSSecurity{
		PrivateKey: leaf.KeyPEM,
		CertChain:  leaf.CertPEM,
	})

	ctx.Cli = &CLI{}
	ctx.Ctx = context.Background()
	ctx.Cli.Ecs.Server = EcsServerCmd{BindIP: "127.0.0.1", Port: freeTestPort(t), Docker: true}

	err = ctx.Cli.Ecs.Server.Run(ctx)
	require.Error(t, err, "empty bearer token with DisableAuth unset must fail closed")
	assert.Contains(t, err.Error(), "--disable-auth")
}

// TestEcsServerCmdRun_DockerExplainedEmptySSLStartsOpen: DisableSSL: true in
// the file is the file's own record that no TLS material is expected, so the
// server must start and serve plain HTTP rather than erroring.
func TestEcsServerCmdRun_DockerExplainedEmptySSLStartsOpen(t *testing.T) {
	ctx, _, _ := newDockerPersistTestCtx(t)
	writeDockerSecurityFileForTest(t, ecs.ECSSecurity{
		BearerToken: "s3cr3t",
		DisableSSL:  true,
	})

	ctx.Cli = &CLI{}
	cctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ctx.Ctx = cctx

	port := freeTestPort(t)
	ctx.Cli.Ecs.Server = EcsServerCmd{BindIP: "127.0.0.1", Port: port, Docker: true}
	cc := &ctx.Cli.Ecs.Server

	done := make(chan error, 1)
	go func() { done <- cc.Run(ctx) }()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	require.NoError(t, waitForEcsServerUp("http", addr, "", 5*time.Second))

	cancel()
	assert.NoError(t, <-done)
}

// TestEcsServerCmdRun_DockerExplainedEmptyAuthStartsOpen: DisableAuth: true in
// the file must start the server with no auth enforced, not error.
func TestEcsServerCmdRun_DockerExplainedEmptyAuthStartsOpen(t *testing.T) {
	ctx, _, _ := newDockerPersistTestCtx(t)

	caCert, err := ctx.Store.GetEcsCaCert()
	require.NoError(t, err)
	caKey, err := ctx.Store.GetEcsCaKey()
	require.NoError(t, err)
	leaf, err := certutil.GenerateLeaf(certutil.KeyPair{CertPEM: caCert, KeyPEM: caKey})
	require.NoError(t, err)

	writeDockerSecurityFileForTest(t, ecs.ECSSecurity{
		PrivateKey:  leaf.KeyPEM,
		CertChain:   leaf.CertPEM,
		DisableAuth: true,
	})

	ctx.Cli = &CLI{}
	cctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ctx.Ctx = cctx

	port := freeTestPort(t)
	ctx.Cli.Ecs.Server = EcsServerCmd{BindIP: "127.0.0.1", Port: port, Docker: true}
	cc := &ctx.Cli.Ecs.Server

	done := make(chan error, 1)
	go func() { done <- cc.Run(ctx) }()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	require.NoError(t, waitForEcsServerUp("https", addr, caCert, 5*time.Second))

	// no auth enforced: an empty bearer token must not be rejected as
	// unauthorized (403). It still 404s -- no default profile was set -- but
	// that is the profile handler, reached only once auth was bypassed.
	c := client.NewECSClient(addr, "", caCert)
	_, err = c.GetProfile()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
	assert.NotContains(t, err.Error(), "403", "DisableAuth: true in the file means no auth is enforced")

	cancel()
	assert.NoError(t, <-done)
}

// TestEcsServerCmdRun_DockerCLIDisableFlagsIgnoredWithFileOverride: the file's
// real material must win over stale/irrelevant CLI flags, and a warning must
// name that the flags have no effect under --docker.
func TestEcsServerCmdRun_DockerCLIDisableFlagsIgnoredWithFileOverride(t *testing.T) {
	tLogger := testlogger.NewTestLogger("DEBUG")
	defer tLogger.Close()
	oldLog := log
	log = tLogger
	defer func() { log = oldLog }()

	ctx, _, _ := newDockerPersistTestCtx(t)

	caCert, err := ctx.Store.GetEcsCaCert()
	require.NoError(t, err)
	caKey, err := ctx.Store.GetEcsCaKey()
	require.NoError(t, err)
	leaf, err := certutil.GenerateLeaf(certutil.KeyPair{CertPEM: caCert, KeyPEM: caKey})
	require.NoError(t, err)

	writeDockerSecurityFileForTest(t, ecs.ECSSecurity{
		PrivateKey:  leaf.KeyPEM,
		CertChain:   leaf.CertPEM,
		BearerToken: "s3cr3t",
	})

	ctx.Cli = &CLI{}
	cctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ctx.Ctx = cctx

	port := freeTestPort(t)
	ctx.Cli.Ecs.Server = EcsServerCmd{
		BindIP:      "127.0.0.1",
		Port:        port,
		Docker:      true,
		DisableSSL:  true,
		DisableAuth: true,
	}
	cc := &ctx.Cli.Ecs.Server

	done := make(chan error, 1)
	go func() { done <- cc.Run(ctx) }()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	require.NoError(t, waitForEcsServerUp("https", addr, caCert, 5*time.Second),
		"the file's real SSL material must win over the CLI flag")

	c := client.NewECSClient(addr, "wrong-token", caCert)
	_, err = c.GetProfile()
	require.Error(t, err, "the file's real bearer token must still be enforced")
	assert.Contains(t, err.Error(), "403")

	cancel()
	assert.NoError(t, <-done)

	var messages []string
	for {
		msg := testlogger.LogMessage{}
		if err := tLogger.GetNext(&msg); err != nil {
			break
		}
		messages = append(messages, msg.Message)
	}
	found := false
	for _, m := range messages {
		if strings.Contains(m, "--docker") && strings.Contains(m, "no effect") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected a warning that --disable-ssl/--disable-auth have no effect under --docker, got: %v", messages)
}

// TestReusablePersistedLeaf exercises the reuse decision directly, one branch
// per case: `ecs docker secrets` only reaches the happy path, so the
// "don't reuse this" rejections need their own coverage.
func TestReusablePersistedLeaf(t *testing.T) {
	// A well-formed leaf that really is signed by the CA the fixture stores,
	// so the "reusable" case is decided by VerifyLeafAgainstCA, not by luck.
	freshLeaf := func(t *testing.T, ctx *RunContext) certutil.KeyPair {
		t.Helper()
		caCert, err := ctx.Store.GetEcsCaCert()
		require.NoError(t, err)
		caKey, err := ctx.Store.GetEcsCaKey()
		require.NoError(t, err)
		leaf, err := certutil.GenerateLeaf(certutil.KeyPair{CertPEM: caCert, KeyPEM: caKey})
		require.NoError(t, err)
		return leaf
	}

	tests := []struct {
		name string
		// setup writes whatever the case needs and returns the CA cert to
		// verify against; an empty return means "no CA configured".
		setup     func(t *testing.T, ctx *RunContext, secPath string) string
		wantReuse bool
	}{
		{
			name: "no CA configured",
			setup: func(t *testing.T, ctx *RunContext, secPath string) string {
				writeSecurityFileForTest(t, secPath, ecs.ECSSecurity{
					PrivateKey: "key", CertChain: freshLeaf(t, ctx).CertPEM,
				})
				return ""
			},
		},
		{
			name: "no security file",
			setup: func(t *testing.T, ctx *RunContext, secPath string) string {
				caCert, err := ctx.Store.GetEcsCaCert()
				require.NoError(t, err)
				require.NoFileExists(t, secPath)
				return caCert
			},
		},
		{
			name: "unparseable security file",
			setup: func(t *testing.T, ctx *RunContext, secPath string) string {
				require.NoError(t, os.MkdirAll(filepath.Dir(secPath), 0700))
				require.NoError(t, os.WriteFile(secPath, []byte("not json"), 0600))
				caCert, err := ctx.Store.GetEcsCaCert()
				require.NoError(t, err)
				return caCert
			},
		},
		{
			name: "no SSL material in the file",
			setup: func(t *testing.T, ctx *RunContext, secPath string) string {
				writeSecurityFileForTest(t, secPath, ecs.ECSSecurity{BearerToken: "s3cr3t"})
				caCert, err := ctx.Store.GetEcsCaCert()
				require.NoError(t, err)
				return caCert
			},
		},
		{
			name: "unparseable certificate",
			setup: func(t *testing.T, ctx *RunContext, secPath string) string {
				writeSecurityFileForTest(t, secPath, ecs.ECSSecurity{
					PrivateKey: "key", CertChain: "not a cert",
				})
				caCert, err := ctx.Store.GetEcsCaCert()
				require.NoError(t, err)
				return caCert
			},
		},
		{
			name: "leaf aged past the refresh threshold",
			setup: func(t *testing.T, ctx *RunContext, secPath string) string {
				writeSecurityFileForTest(t, secPath, ecs.ECSSecurity{
					PrivateKey: "key",
					CertChain:  genTestCertWithNotAfter(t, time.Now().Add(leafRefreshThreshold-time.Hour)),
				})
				caCert, err := ctx.Store.GetEcsCaCert()
				require.NoError(t, err)
				return caCert
			},
		},
		{
			name: "leaf orphaned by a CA rotation",
			setup: func(t *testing.T, ctx *RunContext, secPath string) string {
				writeSecurityFileForTest(t, secPath, ecs.ECSSecurity{
					PrivateKey: "key", CertChain: freshLeaf(t, ctx).CertPEM,
				})
				// rotate after minting, so the leaf is still well inside its
				// own validity window but no longer chains to the stored CA
				rotatedCert, rotatedKey := genTestCA(t)
				require.NoError(t, ctx.Store.SaveEcsCaKeyPair(context.Background(),
					[]byte(rotatedKey), []byte(rotatedCert)))
				return rotatedCert
			},
		},
		{
			name: "fresh leaf signed by the stored CA",
			setup: func(t *testing.T, ctx *RunContext, secPath string) string {
				leaf := freshLeaf(t, ctx)
				writeSecurityFileForTest(t, secPath, ecs.ECSSecurity{
					PrivateKey: leaf.KeyPEM, CertChain: leaf.CertPEM,
				})
				caCert, err := ctx.Store.GetEcsCaCert()
				require.NoError(t, err)
				return caCert
			},
			wantReuse: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, secPath, _ := newDockerPersistTestCtx(t)
			caCert := tt.setup(t, ctx, secPath)

			privateKey, certChain := reusablePersistedLeaf(ctx.Cli.Ecs.SecretsDir, caCert)
			if !tt.wantReuse {
				assert.Empty(t, privateKey)
				assert.Empty(t, certChain)
				return
			}

			sec := readSecurityFileForTest(t, secPath)
			assert.Equal(t, sec.PrivateKey, privateKey)
			assert.Equal(t, sec.CertChain, certChain)
		})
	}
}

// TestRefreshDockerSecurityFileIfStale_MintFails: the CA is unreadable, so the
// refresh cannot proceed.  The existing file has to survive untouched -- a
// half-written security config would break a running container.
func TestRefreshDockerSecurityFileIfStale_MintFails(t *testing.T) {
	ctx, secPath, _ := newDockerPersistTestCtx(t)

	writeSecurityFileForTest(t, secPath, ecs.ECSSecurity{
		PrivateKey:  "key",
		CertChain:   genTestCertWithNotAfter(t, time.Now().Add(leafRefreshThreshold-time.Hour)),
		BearerToken: "s3cr3t",
	})
	before := readSecurityFileForTest(t, secPath)

	ctx.Store = &errStore{
		SecureStorage: ctx.Store,
		getEcsCaCert:  func() (string, error) { return "", fmt.Errorf("store is on fire") },
	}

	refreshDockerSecurityFileIfStale(ctx)
	assert.Equal(t, before, readSecurityFileForTest(t, secPath))
}

// TestRefreshDockerSecurityFileIfStale_CARemoved: `setup ecs ssl --delete`
// leaves a stale leaf with no CA behind it.  There is nothing to re-mint from,
// so the file is left as-is rather than being rewritten without SSL material.
func TestRefreshDockerSecurityFileIfStale_CARemoved(t *testing.T) {
	ctx, secPath, _ := newDockerPersistTestCtx(t)

	writeSecurityFileForTest(t, secPath, ecs.ECSSecurity{
		PrivateKey:  "key",
		CertChain:   genTestCertWithNotAfter(t, time.Now().Add(leafRefreshThreshold-time.Hour)),
		BearerToken: "s3cr3t",
	})
	before := readSecurityFileForTest(t, secPath)

	require.NoError(t, ctx.Store.DeleteEcsCaKeyPair(context.Background()))

	refreshDockerSecurityFileIfStale(ctx)
	assert.Equal(t, before, readSecurityFileForTest(t, secPath))
}

// TestRefreshDockerSecurityFileIfStale_WriteFails: a read-only security file
// must not turn background maintenance into a hard failure of whatever command
// the hook is piggybacking on.
func TestRefreshDockerSecurityFileIfStale_WriteFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permissions")
	}

	ctx, secPath, _ := newDockerPersistTestCtx(t)

	writeSecurityFileForTest(t, secPath, ecs.ECSSecurity{
		PrivateKey:  "key",
		CertChain:   genTestCertWithNotAfter(t, time.Now().Add(leafRefreshThreshold-time.Hour)),
		BearerToken: "s3cr3t",
	})
	before := readSecurityFileForTest(t, secPath)
	require.NoError(t, os.Chmod(secPath, 0400))

	assert.NotPanics(t, func() { refreshDockerSecurityFileIfStale(ctx) })

	require.NoError(t, os.Chmod(secPath, 0600))
	assert.Equal(t, before, readSecurityFileForTest(t, secPath))
}

// TestEcsDockerSecretsCmdRun_CAReadFails: an unreadable CA is a hard error,
// not a silent fallback to writing a config with no SSL material in it.
func TestEcsDockerSecretsCmdRun_CAReadFails(t *testing.T) {
	ctx, secPath, _ := newDockerPersistTestCtx(t)
	ctx.Store = &errStore{
		SecureStorage: ctx.Store,
		getEcsCaCert:  func() (string, error) { return "", fmt.Errorf("store is on fire") },
	}

	err := (&EcsDockerSecretsCmd{}).Run(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store is on fire")
	assert.NoFileExists(t, secPath, "a failed run should not leave a partial config behind")
}

// TestEcsDockerSecretsCmdRun_BearerTokenReadFails: an unreadable token is a
// hard error too -- writing the config without it would quietly produce a server
// with HTTP Auth off.
func TestEcsDockerSecretsCmdRun_BearerTokenReadFails(t *testing.T) {
	ctx, secPath, _ := newDockerPersistTestCtx(t)
	ctx.Store = &errStore{
		SecureStorage:     ctx.Store,
		getEcsBearerToken: func() (string, error) { return "", fmt.Errorf("store is on fire") },
	}

	err := (&EcsDockerSecretsCmd{}).Run(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store is on fire")
	assert.NoFileExists(t, secPath)
}

// TestEcsDockerSecretsCmdRun_CAKeyReadFails covers the second half of the
// CA fetch: the cert reads fine but the key does not.
func TestEcsDockerSecretsCmdRun_CAKeyReadFails(t *testing.T) {
	ctx, secPath, _ := newDockerPersistTestCtx(t)
	ctx.Store = &errStore{
		SecureStorage: ctx.Store,
		getEcsCaKey:   func() (string, error) { return "", fmt.Errorf("store is on fire") },
	}

	err := (&EcsDockerSecretsCmd{}).Run(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store is on fire")
	assert.NoFileExists(t, secPath)
}

// TestEcsDockerSecretsCmdRun_TokenFileWriteFails: the security file and its
// bearer-token companion are written together, and a failure on the companion
// has to surface rather than leaving the user with a half-provisioned mount.
func TestEcsDockerSecretsCmdRun_TokenFileWriteFails(t *testing.T) {
	ctx, _, tokenPath := newDockerPersistTestCtx(t)

	// a non-empty directory where the token file needs to be
	require.NoError(t, os.MkdirAll(tokenPath, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(tokenPath, "child"), []byte("x"), 0600))

	err := (&EcsDockerSecretsCmd{}).Run(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to write bearer token file")
}

// writeDockerSecurityFileForTest points the container-side security file path at
// a host file, since /app/.aws-sso/ecs/docker-secret.json cannot be created
// outside the container.
func writeDockerSecurityFileForTest(t *testing.T, sec ecs.ECSSecurity) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "docker-secret.json")
	writeSecurityFileForTest(t, path, sec)

	ecs.TestContainerFilePathOverride = path
	t.Cleanup(func() { ecs.TestContainerFilePathOverride = "" })
}

// TestEcsServerCmdRun_DockerReadsPersistedConfig is the flip side of the
// fail-closed tests: given the security file the host wrote, `--docker` comes up
// with exactly the posture the file describes -- TLS from the persisted leaf and
// HTTP Auth from the persisted token -- with no SecureStore of its own.  This is
// what has to keep working across `docker compose restart` and recreation.
func TestEcsServerCmdRun_DockerReadsPersistedConfig(t *testing.T) {
	ctx, _, _ := newDockerPersistTestCtx(t)

	caCert, err := ctx.Store.GetEcsCaCert()
	require.NoError(t, err)
	caKey, err := ctx.Store.GetEcsCaKey()
	require.NoError(t, err)
	leaf, err := certutil.GenerateLeaf(certutil.KeyPair{CertPEM: caCert, KeyPEM: caKey})
	require.NoError(t, err)

	writeDockerSecurityFileForTest(t, ecs.ECSSecurity{
		PrivateKey:  leaf.KeyPEM,
		CertChain:   leaf.CertPEM,
		BearerToken: "s3cr3t",
	})

	// the container has no SecureStore: everything comes from the file
	ctx.Store = nil
	ctx.Cli = &CLI{}
	cctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ctx.Ctx = cctx

	port := freeTestPort(t)
	ctx.Cli.Ecs.Server = EcsServerCmd{BindIP: "127.0.0.1", Port: port, Docker: true}
	cc := &ctx.Cli.Ecs.Server

	done := make(chan error, 1)
	go func() { done <- cc.Run(ctx) }()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	require.NoError(t, waitForEcsServerUp("https", addr, caCert, 5*time.Second),
		"the persisted leaf should be served over TLS")

	// and the persisted token is enforced: the credential routes sit behind auth
	c := client.NewECSClient(addr, "wrong-token", caCert)
	_, err = c.GetProfile()
	require.Error(t, err, "a wrong bearer token must be rejected")
	assert.Contains(t, err.Error(), "403")

	cancel()
	assert.NoError(t, <-done)
}

// TestEcsServerCmdRun_DockerMismatchedKeyPair: a security file whose key and
// certificate don't belong together must fail the command outright, not start a
// server that cannot complete a handshake.
func TestEcsServerCmdRun_DockerMismatchedKeyPair(t *testing.T) {
	ctx, _, _ := newDockerPersistTestCtx(t)

	caCert, err := ctx.Store.GetEcsCaCert()
	require.NoError(t, err)
	caKey, err := ctx.Store.GetEcsCaKey()
	require.NoError(t, err)
	leaf, err := certutil.GenerateLeaf(certutil.KeyPair{CertPEM: caCert, KeyPEM: caKey})
	require.NoError(t, err)
	other, err := certutil.GenerateLeaf(certutil.KeyPair{CertPEM: caCert, KeyPEM: caKey})
	require.NoError(t, err)

	writeDockerSecurityFileForTest(t, ecs.ECSSecurity{
		PrivateKey:  other.KeyPEM, // belongs to a different leaf
		CertChain:   leaf.CertPEM,
		BearerToken: "s3cr3t",
	})

	ctx.Store = nil
	ctx.Cli = &CLI{}
	ctx.Ctx = context.Background()
	ctx.Cli.Ecs.Server = EcsServerCmd{BindIP: "127.0.0.1", Port: freeTestPort(t), Docker: true}

	err = ctx.Cli.Ecs.Server.Run(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ECS server certificate")
}

// TestEcsServerCmdRun_DockerUnparseableConfig: a corrupt security file is an
// error, not a fallback to an open server.
func TestEcsServerCmdRun_DockerUnparseableConfig(t *testing.T) {
	ctx, _, _ := newDockerPersistTestCtx(t)

	path := filepath.Join(t.TempDir(), "docker-secret.json")
	require.NoError(t, os.WriteFile(path, []byte("not json"), 0600))
	ecs.TestContainerFilePathOverride = path
	t.Cleanup(func() { ecs.TestContainerFilePathOverride = "" })

	ctx.Store = nil
	ctx.Cli = &CLI{}
	ctx.Ctx = context.Background()
	ctx.Cli.Ecs.Server = EcsServerCmd{BindIP: "127.0.0.1", Port: freeTestPort(t), Docker: true}

	assert.Error(t, ctx.Cli.Ecs.Server.Run(ctx))
}

// TestEcsServerCmdRun_ListenFails: an unusable bind address fails before any
// security material is touched.
func TestEcsServerCmdRun_ListenFails(t *testing.T) {
	ctx, _, _ := newDockerPersistTestCtx(t)
	ctx.Cli = &CLI{}
	ctx.Cli.Ecs.Server = EcsServerCmd{BindIP: "999.999.999.999", Port: 4144}

	assert.Error(t, ctx.Cli.Ecs.Server.Run(ctx))
}

// TestEcsServerCmdRun_NativeNoAuthWarns: no bearer token configured and no
// --disable-auth is a misconfiguration the user should hear about, and the
// server still comes up open rather than refusing to start.
func TestEcsServerCmdRun_NativeNoAuthWarns(t *testing.T) {
	tLogger := testlogger.NewTestLogger("DEBUG")
	defer tLogger.Close()

	oldLog := log
	log = tLogger
	defer func() { log = oldLog }()

	ctx := newSelfSignedTestCtx(t)
	cctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ctx.Ctx = cctx

	port := freeTestPort(t)
	ctx.Cli.Ecs.Server = EcsServerCmd{BindIP: "127.0.0.1", Port: port}
	cc := &ctx.Cli.Ecs.Server

	done := make(chan error, 1)
	go func() { done <- cc.Run(ctx) }()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	require.NoError(t, waitForEcsServerUp("http", addr, "", 5*time.Second))

	cancel()
	assert.NoError(t, <-done)

	var messages []string
	for {
		msg := testlogger.LogMessage{}
		if err := tLogger.GetNext(&msg); err != nil {
			break
		}
		messages = append(messages, msg.Message)
	}
	assert.Contains(t, messages, "HTTP Auth: disabled. Use 'aws-sso setup ecs auth' to enable")
	assert.Contains(t, messages, "SSL/TLS: disabled.  Use 'aws-sso setup ecs ssl' to enable")
}

// TestEcsDockerSecretsCmdRun_CustomSecretsDir covers --secrets-dir end to end:
// both files land where the user asked, and nothing is left in the default
// config-dir location.
func TestEcsDockerSecretsCmdRun_CustomSecretsDir(t *testing.T) {
	secretsDir := filepath.Join(t.TempDir(), "compose", "secrets")
	ctx, secPath, tokenPath := newDockerPersistTestCtxIn(t, secretsDir)

	cc := &EcsDockerSecretsCmd{}
	require.NoError(t, cc.Run(ctx))

	sec := readSecurityFileForTest(t, secPath)
	assert.Equal(t, "s3cr3t", sec.BearerToken)
	assert.NotEmpty(t, sec.CertChain)

	data, err := os.ReadFile(tokenPath) // nolint:gosec
	require.NoError(t, err)
	assert.Equal(t, "Bearer s3cr3t", string(data))

	assert.NoDirExists(t, ecs.HostMountPoint(""),
		"an explicit --secrets-dir must not also populate the default location")
}

// TestEcsDockerSecretsCmdRun_RelativeSecretsDir covers the docker bind-mount
// requirement: a relative --secrets-dir has to resolve to an absolute path.
func TestEcsDockerSecretsCmdRun_RelativeSecretsDir(t *testing.T) {
	t.Chdir(t.TempDir())

	ctx, _, _ := newDockerPersistTestCtxIn(t, "secrets")
	require.NoError(t, (&EcsDockerSecretsCmd{}).Run(ctx))

	dir := ecs.HostMountPoint("secrets")
	assert.True(t, filepath.IsAbs(dir), "docker bind mounts reject a relative source")
	assert.FileExists(t, filepath.Join(dir, "docker-secret.json"))
}

// TestRefreshDockerSecurityFileIfStale_CustomSecretsDir makes sure the
// opportunistic refresh on `ecs load`/`list`/`profile` follows --secrets-dir
// rather than only maintaining the default location.
func TestRefreshDockerSecurityFileIfStale_CustomSecretsDir(t *testing.T) {
	secretsDir := filepath.Join(t.TempDir(), "secrets")
	ctx, secPath, _ := newDockerPersistTestCtxIn(t, secretsDir)

	caCert, err := ctx.Store.GetEcsCaCert()
	require.NoError(t, err)
	stale := genTestCertWithNotAfter(t, time.Now().Add(leafRefreshThreshold-time.Hour))
	writeSecurityFileForTest(t, secPath, ecs.ECSSecurity{
		PrivateKey: "key", CertChain: stale, BearerToken: "s3cr3t",
	})

	refreshDockerSecurityFileIfStale(ctx)

	got := readSecurityFileForTest(t, secPath)
	assert.NotEqual(t, stale, got.CertChain, "the stale leaf in --secrets-dir should be re-minted")
	assert.Equal(t, "s3cr3t", got.BearerToken, "the bearer token is preserved")
	require.NoError(t, certutil.VerifyLeafAgainstCA(got.CertChain, caCert))

	assert.NoDirExists(t, ecs.HostMountPoint(""),
		"the default location must not be created as a side effect")
}

// TestEcsContainerMounts covers the bind mount `ecs docker start` hands the
// container.  Extracted from EcsDockerStartCmd.Run, which needs a live Docker
// daemon and so cannot be exercised here.
func TestEcsContainerMounts(t *testing.T) {
	newDockerPersistTestCtx(t) // isolates $HOME so HostMountPoint("") resolves

	mounts := ecsContainerMounts("/srv/secrets")
	require.Len(t, mounts, 1)
	assert.Equal(t, "/srv/secrets", mounts[0].Source)
	assert.Equal(t, ecs.CONTAINER_MOUNT_POINT, mounts[0].Target)
	assert.True(t, mounts[0].ReadOnly, "the server only reads the security file")

	assert.Equal(t, ecs.HostMountPoint(""), ecsContainerMounts("")[0].Source,
		"no --secrets-dir falls back to the config-dir location")
}

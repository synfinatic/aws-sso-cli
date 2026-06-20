//go:build e2etests

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
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/synfinatic/aws-sso-cli/internal/awsmock"
	sso "github.com/synfinatic/aws-sso-cli/internal/sso"
	ssoauth "github.com/synfinatic/aws-sso-cli/internal/sso/auth"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

// TestE2EList verifies that ListCmd.Run outputs the cached roles to stdout.
func TestE2EList(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)

	ctx := newRunContext(setup, AUTH_SKIP)
	ctx.Cli.List = ListCmd{Sort: "AccountId"}

	output := captureStdout(func() {
		err := (&ctx.Cli.List).Run(ctx)
		require.NoError(t, err)
	})

	assert.Contains(t, output, "ReadOnly",
		"list output should contain the cached role name")
	assert.Contains(t, output, "123456789012",
		"list output should contain the account ID")
}

// TestE2ESubprocessExitCodeRace is a subprocess regression test for the race
// condition introduced in #1379: the goroutine watching appCtx.Done() fires when
// the deferred stop() cancels the context on a normal return from main(), causing
// successful commands to exit non-zero. This breaks `aws-sso process` when used
// as an AWS credential_process — the SDK discards stdout when exit code != 0.
//
// Our in-process e2e tests bypass main() entirely and never exercise the
// signal-handler goroutine. This test runs the real binary as a subprocess to
// catch the race.
//
// `list` is used because it satisfies all three requirements: it returns normally
// from main() (triggering the defer stop() race path), it uses AUTH_SKIP (so no
// SSO auth token check is needed), and it reads only from the local cache file
// (no SSO network calls during the subprocess run).
func TestE2ESubprocessExitCodeRace(t *testing.T) {
	// Build the real binary from the current package directory.
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "aws-sso-e2e")
	buildOut, err := exec.Command("go", "build", "-o", binPath, ".").CombinedOutput()
	require.NoError(t, err, "go build: %s", buildOut)

	// Use an isolated HOME so the binary resolves its cache path to a directory
	// we control: $HOME/.config/aws-sso/cache.json.
	tempHome := t.TempDir()
	cacheDir := filepath.Join(tempHome, ".config", "aws-sso")
	require.NoError(t, os.MkdirAll(cacheDir, 0700))

	server := awsmock.NewMockAWSServer()
	t.Cleanup(server.Close)

	configPath := writeTestConfig(t, tempHome, server.URL(), "Default", nil, "device_code", "")
	cachePath := filepath.Join(cacheDir, "cache.json")
	storePath := filepath.Join(tempHome, "store.json")

	settings, err := sso.LoadSettings(configPath, cachePath, DEFAULT_CONFIG, sso.OverrideSettings{})
	require.NoError(t, err)

	storeCtx := context.Background()
	store, err := storage.OpenJsonStore(storeCtx, storePath)
	require.NoError(t, err)

	ssoConf, err := settings.GetSelectedSSO("Default")
	require.NoError(t, err)
	ssoName, err := settings.GetSelectedSSOName("Default")
	require.NoError(t, err)

	// Temporarily override AwsSSO so populateCache can reach the mock server.
	origAwsSSO := AwsSSO
	AwsSSO = ssoauth.NewAWSSSOForTest(ssoConf, store, server.URL())
	t.Cleanup(func() { AwsSSO = origAwsSSO })

	setup := &e2eSetup{
		Server:   server,
		Settings: settings,
		Store:    store,
		SSOConf:  ssoConf,
		SSOName:  ssoName,
		TempDir:  tempHome,
	}
	// Populate cache via the mock server so `list` has roles to display.
	// No preAuth needed: list uses AUTH_SKIP and never checks the auth token.
	populateCache(t, setup)

	// Build subprocess env: inherit everything except vars that would redirect
	// HOME, the XDG cache dir, or the config file path.
	subEnv := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		k := strings.SplitN(kv, "=", 2)[0]
		switch k {
		case "HOME", "XDG_CONFIG_HOME", "AWS_SSO_CONFIG":
			// replaced / omitted below
		default:
			subEnv = append(subEnv, kv)
		}
	}
	subEnv = append(subEnv, "HOME="+tempHome)

	var stderr bytes.Buffer
	cmd := exec.Command(binPath, "--config", configPath, "list")
	cmd.Env = subEnv
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr

	err = cmd.Run()
	assert.NoError(t, err,
		"aws-sso list must exit 0 — non-zero exit indicates the SIGINT handler "+
			"race where stop() cancels appCtx and the goroutine calls os.Exit(1) "+
			"before the runtime exits cleanly (regression: #1379); stderr: %s",
		stderr.String())
}

// TestE2EListPrefix verifies that --prefix filters roles by field value prefix.
func TestE2EListPrefix(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)

	ctx := newRunContext(setup, AUTH_SKIP)
	ctx.Cli.List = ListCmd{Sort: "AccountId", Prefix: "AccountId=123"}

	output := captureStdout(func() {
		err := (&ctx.Cli.List).Run(ctx)
		require.NoError(t, err)
	})

	assert.Contains(t, output, "ReadOnly", "matching account should appear")
}

// TestE2EListPrefixMissingEquals verifies that a --prefix without '=' returns an error.
func TestE2EListPrefixMissingEquals(t *testing.T) {
	setup := newE2ESetup(t)
	populateCache(t, setup)

	ctx := newRunContext(setup, AUTH_SKIP)
	ctx.Cli.List = ListCmd{Sort: "AccountId", Prefix: "AccountId"}

	err := (&ctx.Cli.List).Run(ctx)
	assert.ErrorContains(t, err, "format of <FieldName>=<Prefix>")
}

// TestE2EListPrefixInvalidField verifies that an unknown --prefix field name returns an error.
func TestE2EListPrefixInvalidField(t *testing.T) {
	setup := newE2ESetup(t)
	populateCache(t, setup)

	ctx := newRunContext(setup, AUTH_SKIP)
	ctx.Cli.List = ListCmd{Sort: "AccountId", Prefix: "NoSuchField=x"}

	err := (&ctx.Cli.List).Run(ctx)
	assert.ErrorContains(t, err, "valid field")
}

// TestE2EListCSV verifies that the CSV flag produces comma-separated output.
func TestE2EListCSV(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)

	ctx := newRunContext(setup, AUTH_SKIP)
	ctx.Cli.List = ListCmd{Sort: "AccountId", CSV: true, Fields: []string{"AccountId", "RoleName"}}

	output := captureStdout(func() {
		err := (&ctx.Cli.List).Run(ctx)
		require.NoError(t, err)
	})

	assert.Contains(t, output, ",", "CSV output should contain commas")
	assert.Contains(t, output, "ReadOnly")
}

// TestE2EListSort verifies ascending sort by RoleName puts PowerUser before ReadOnly.
func TestE2EListSort(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)

	ctx := newRunContext(setup, AUTH_SKIP)
	ctx.Cli.List = ListCmd{Sort: "RoleName", Fields: []string{"RoleName"}}

	output := captureStdout(func() {
		err := (&ctx.Cli.List).Run(ctx)
		require.NoError(t, err)
	})

	powerIdx := strings.Index(output, "PowerUser")
	readOnlyIdx := strings.Index(output, "ReadOnly")
	assert.True(t, powerIdx < readOnlyIdx, "ascending sort: PowerUser should appear before ReadOnly")
}

// TestE2EListSortReverse verifies descending sort by RoleName puts ReadOnly before PowerUser.
func TestE2EListSortReverse(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)

	ctx := newRunContext(setup, AUTH_SKIP)
	ctx.Cli.List = ListCmd{Sort: "RoleName", Reverse: true, Fields: []string{"RoleName"}}

	output := captureStdout(func() {
		err := (&ctx.Cli.List).Run(ctx)
		require.NoError(t, err)
	})

	readOnlyIdx := strings.Index(output, "ReadOnly")
	powerIdx := strings.Index(output, "PowerUser")
	assert.True(t, readOnlyIdx < powerIdx, "descending sort: ReadOnly should appear before PowerUser")
}

// TestE2EListUnsupportedField verifies that an unknown field name returns an error.
func TestE2EListUnsupportedField(t *testing.T) {
	setup := newE2ESetup(t)
	populateCache(t, setup)

	ctx := newRunContext(setup, AUTH_SKIP)
	ctx.Cli.List = ListCmd{Sort: "AccountId", Fields: []string{"NoSuchField"}}

	err := (&ctx.Cli.List).Run(ctx)
	assert.ErrorContains(t, err, "unsupported field")
}

// TestE2EListFields verifies that the -f flag prints the available fields table.
func TestE2EListFields(t *testing.T) {
	setup := newE2ESetup(t)

	ctx := newRunContext(setup, AUTH_SKIP)
	ctx.Cli.List = ListCmd{ListFields: true}

	output := captureStdout(func() {
		err := (&ctx.Cli.List).Run(ctx)
		require.NoError(t, err)
	})

	assert.Contains(t, output, "AccountId", "fields table should list AccountId")
	assert.Contains(t, output, "RoleName", "fields table should list RoleName")
}

// TestE2EDefaultCmd verifies that DefaultCmd.Run prints the cached roles table.
func TestE2EDefaultCmd(t *testing.T) {
	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)

	ctx := newRunContext(setup, AUTH_SKIP)

	output := captureStdout(func() {
		err := (&DefaultCmd{}).Run(ctx)
		require.NoError(t, err)
	})

	assert.Contains(t, output, "ReadOnly")
	assert.Contains(t, output, "123456789012")
}

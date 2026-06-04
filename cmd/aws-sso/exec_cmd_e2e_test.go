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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ssoauth "github.com/synfinatic/aws-sso-cli/internal/sso/auth"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

// TestE2EExec verifies that ExecCmd.Run injects credentials into the subprocess
// environment and runs it successfully.
func TestE2EExec(t *testing.T) {
	// checkAwsEnvironment rejects conflicting AWS_ vars; clear them for the test.
	for _, v := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE"} {
		if old, ok := os.LookupEnv(v); ok {
			t.Cleanup(func() { os.Setenv(v, old) })
			os.Unsetenv(v)
		}
	}

	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Exec = ExecCmd{
		AccountId: AccountID(123456789012),
		Role:      "ReadOnly",
		Cmd:       "/bin/sh",
		Args:      []string{"-c", "exit 0"},
	}

	err := (&ctx.Cli.Exec).Run(ctx)
	assert.NoError(t, err, "exec should run the subprocess without error")
}

// TestE2EExecRegion_DefaultNoOverwrite verifies that exec does NOT override
// $AWS_DEFAULT_REGION in the subprocess when the user has set it to a value
// not managed by aws-sso (no --overwrite-env).
func TestE2EExecRegion_DefaultNoOverwrite(t *testing.T) {
	for _, v := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE"} {
		unsetEnvForTest(t, v)
	}
	t.Setenv("AWS_DEFAULT_REGION", "eu-west-1")
	t.Setenv("AWS_SSO_DEFAULT_REGION", "")

	setup := newE2ESetupWithRegion(t, "us-east-1")
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Exec = ExecCmd{
		AccountId: AccountID(123456789012),
		Role:      "ReadOnly",
		Cmd:       "/bin/sh",
		Args:      []string{"-c", "echo REGION=$AWS_DEFAULT_REGION"},
	}

	output := captureStdout(func() {
		err := (&ctx.Cli.Exec).Run(ctx)
		require.NoError(t, err)
	})

	// Subprocess must inherit the user's region; the configured us-east-1 must not appear.
	assert.Contains(t, output, "REGION=eu-west-1",
		"subprocess should see the user-set AWS_DEFAULT_REGION without --overwrite-env")
	assert.NotContains(t, output, "REGION=us-east-1",
		"subprocess must not receive the configured region without --overwrite-env")
}

// TestE2EExecRegion_OverwriteEnv verifies that --overwrite-env causes exec to inject
// the configured region into the subprocess environment, replacing any user-set value.
func TestE2EExecRegion_OverwriteEnv(t *testing.T) {
	// --overwrite-env skips checkAwsEnvironment, so credential vars may be set.
	t.Setenv("AWS_ACCESS_KEY_ID", "old-key")
	t.Setenv("AWS_DEFAULT_REGION", "eu-west-1") // user-set region to be overridden
	t.Setenv("AWS_SSO_DEFAULT_REGION", "")

	setup := newE2ESetupWithRegion(t, "us-east-1")
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Exec = ExecCmd{
		AccountId:    AccountID(123456789012),
		Role:         "ReadOnly",
		OverwriteEnv: true,
		Cmd:          "/bin/sh",
		Args:         []string{"-c", "echo REGION=$AWS_DEFAULT_REGION"},
	}

	output := captureStdout(func() {
		err := (&ctx.Cli.Exec).Run(ctx)
		require.NoError(t, err)
	})

	// Subprocess must receive the configured region; the user's eu-west-1 must be gone.
	assert.Contains(t, output, "REGION=us-east-1",
		"exec --overwrite-env must inject the configured AWS_DEFAULT_REGION into the subprocess")
	assert.NotContains(t, output, "REGION=eu-west-1",
		"exec --overwrite-env must strip the user-set AWS_DEFAULT_REGION from the subprocess")
}

// TestE2EExecOverwriteEnv_CredentialStripping verifies that --overwrite-env strips pre-existing
// AWS_* credential variables from the subprocess environment and injects fresh credentials.
func TestE2EExecOverwriteEnv_CredentialStripping(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "old-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "old-secret")

	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Exec = ExecCmd{
		AccountId:    AccountID(123456789012),
		Role:         "ReadOnly",
		OverwriteEnv: true,
		Cmd:          "/bin/sh",
		Args:         []string{"-c", "echo KEY=$AWS_ACCESS_KEY_ID SECRET=$AWS_SECRET_ACCESS_KEY"},
	}

	output := captureStdout(func() {
		err := (&ctx.Cli.Exec).Run(ctx)
		require.NoError(t, err)
	})

	assert.Contains(t, output, "KEY=AKIDTEST12345",
		"subprocess must receive the new AWS_ACCESS_KEY_ID from the role credentials")
	assert.Contains(t, output, "SECRET=SECRETTEST12345",
		"subprocess must receive the new AWS_SECRET_ACCESS_KEY from the role credentials")
	assert.NotContains(t, output, "old-key",
		"subprocess must not see the pre-existing AWS_ACCESS_KEY_ID when -O is used")
	assert.NotContains(t, output, "old-secret",
		"subprocess must not see the pre-existing AWS_SECRET_ACCESS_KEY when -O is used")
}

// TestE2EExecConflictingEnv_Fatal verifies that exec exits non-zero when a conflicting AWS_*
// credential variable is set in the environment and --overwrite-env is not used. Because
// log.Fatal kills the process, this test runs the real binary as a subprocess.
func TestE2EExecConflictingEnv_Fatal(t *testing.T) {
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "aws-sso-e2e")
	buildOut, err := exec.Command("go", "build", "-o", binPath, ".").CombinedOutput()
	require.NoError(t, err, "go build: %s", buildOut)

	setup := newE2ESetup(t)
	preAuth(t, setup) // seed a valid auth token so checkAuth in main.go passes

	// The binary resolves the JsonStore lock file and cache under $HOME/.config/aws-sso/.
	require.NoError(t, os.MkdirAll(filepath.Join(setup.TempDir, ".config", "aws-sso"), 0700))

	subEnv := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		k := strings.SplitN(kv, "=", 2)[0]
		switch k {
		case "HOME", "XDG_CONFIG_HOME", "AWS_SSO_CONFIG",
			"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE":
		default:
			subEnv = append(subEnv, kv)
		}
	}
	subEnv = append(subEnv, "HOME="+setup.TempDir)
	subEnv = append(subEnv, "AWS_ACCESS_KEY_ID=conflict-key")

	configPath := filepath.Join(setup.TempDir, "config.yaml")
	var stderr bytes.Buffer
	cmd := exec.Command(binPath,
		"--config", configPath,
		"exec", "--account", "123456789012", "--role", "ReadOnly",
		"/bin/sh", "-c", "exit 0",
	)
	cmd.Env = subEnv
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr

	err = cmd.Run()
	assert.Error(t, err,
		"exec without -O must exit non-zero when AWS_ACCESS_KEY_ID is set in the environment")
	assert.Contains(t, stderr.String(), "conflicting",
		"stderr should name the conflicting environment variable")
}

// TestE2EExecSTSRefresh verifies that exec with --sts-refresh passes the
// refresh flag through to GetRoleCredentials and still runs the subprocess.
func TestE2EExecSTSRefresh(t *testing.T) {
	for _, v := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE"} {
		unsetEnvForTest(t, v)
	}

	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Exec = ExecCmd{
		AccountId:  AccountID(123456789012),
		Role:       "ReadOnly",
		STSRefresh: true,
		Cmd:        "/bin/sh",
		Args:       []string{"-c", "exit 0"},
	}

	err := (&ctx.Cli.Exec).Run(ctx)
	assert.NoError(t, err, "exec --sts-refresh should run the subprocess without error")
}

// TestE2EMultipleSSO_Exec mirrors TestE2EMultipleSSO_Selection for the exec
// command, verifying that both the explicit --sso flag and DefaultSSO config
// route credential fetches to the correct SSO instance.
func TestE2EMultipleSSO_Exec(t *testing.T) {
	t.Run("explicit_sso_flag_overrides_default", func(t *testing.T) {
		for _, v := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE"} {
			unsetEnvForTest(t, v)
		}

		setup := newE2ESetupMultiSSO(t, "Default")

		secondaryConf, err := setup.Settings.GetSelectedSSO("Secondary")
		require.NoError(t, err)
		AwsSSO = ssoauth.NewAWSSSOForTest(secondaryConf, setup.Store, setup.Server.URL())
		setup.SSOConf = secondaryConf
		setup.SSOName = "Secondary"
		setup.Settings.Cache.SetSSOName("Secondary")

		preAuth(t, setup)
		populateCache(t, setup)
		queueRoleCredentials(setup.Server)

		ctx := newRunContext(setup, AUTH_REQUIRED)
		ctx.Cli.SSO = "Secondary"
		ctx.Cli.Exec = ExecCmd{
			AccountId: AccountID(123456789012),
			Role:      "ReadOnly",
			Cmd:       "/bin/sh",
			Args:      []string{"-c", "echo KEY=$AWS_ACCESS_KEY_ID"},
		}

		output := captureStdout(func() {
			err := (&ctx.Cli.Exec).Run(ctx)
			require.NoError(t, err)
		})

		assert.Contains(t, output, "KEY=AKIDTEST12345",
			"exec should succeed using Secondary SSO via --sso flag")

		defaultConf, _ := setup.Settings.GetSelectedSSO("Default")
		defaultKey := ssoauth.NewAWSSSOForTest(defaultConf, setup.Store, setup.Server.URL()).StoreKey()
		var defaultToken storage.CreateTokenResponse
		assert.Error(t, setup.Store.GetCreateTokenResponse(defaultKey, &defaultToken),
			"Default SSO should not have been authenticated")
	})

	t.Run("default_sso_from_config_is_used", func(t *testing.T) {
		for _, v := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE"} {
			unsetEnvForTest(t, v)
		}

		// Config has DefaultSSO=Secondary; leave ctx.Cli.SSO empty.
		setup := newE2ESetupMultiSSO(t, "Secondary")

		preAuth(t, setup)
		populateCache(t, setup)
		queueRoleCredentials(setup.Server)

		ctx := newRunContext(setup, AUTH_REQUIRED)
		// ctx.Cli.SSO intentionally left empty — DefaultSSO from config applies.
		ctx.Cli.Exec = ExecCmd{
			AccountId: AccountID(123456789012),
			Role:      "ReadOnly",
			Cmd:       "/bin/sh",
			Args:      []string{"-c", "echo KEY=$AWS_ACCESS_KEY_ID"},
		}

		output := captureStdout(func() {
			err := (&ctx.Cli.Exec).Run(ctx)
			require.NoError(t, err)
		})

		assert.Contains(t, output, "KEY=AKIDTEST12345",
			"exec should succeed using Secondary SSO from DefaultSSO config")
	})
}

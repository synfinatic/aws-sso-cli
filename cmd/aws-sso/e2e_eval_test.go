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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/synfinatic/aws-sso-cli/internal/awsmock"
	ssoauth "github.com/synfinatic/aws-sso-cli/internal/sso/auth"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

// TestE2EEval verifies that EvalCmd.Run outputs shell export statements with
// the AWS credentials for the requested role.
func TestE2EEval(t *testing.T) {
	t.Setenv("SHELL", "/bin/bash")

	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Eval = EvalCmd{
		AccountId: AccountID(123456789012),
		Role:      "ReadOnly",
	}

	output := captureStdout(func() {
		err := (&EvalCmd{}).Run(ctx)
		require.NoError(t, err)
	})

	assert.Contains(t, output, `export AWS_ACCESS_KEY_ID="AKIDTEST12345"`,
		"eval output should export the access key ID")
	assert.Contains(t, output, `export AWS_SECRET_ACCESS_KEY="SECRETTEST12345"`,
		"eval output should export the secret access key")
	assert.Contains(t, output, `export AWS_SESSION_TOKEN="TOKENTEST12345"`,
		"eval output should export the session token")
}

// TestE2EEval_RoleChain verifies that EvalCmd resolves credentials for a role
// configured with Via: (STS AssumeRole chaining), exercising the full
// GetRoleCredentials(BaseRole) → AssumeRole(TargetRole) pipeline.
func TestE2EEval_RoleChain(t *testing.T) {
	t.Setenv("SHELL", "/bin/bash")

	setup := newE2ESetupRoleChain(t)
	preAuth(t, setup)

	// Populate cache with both BaseRole and TargetRole.
	setup.Server.SSO.QueueListAccounts(awsmock.ListAccountsResponse{
		AccountList: []awsmock.AccountInfo{
			{AccountID: "123456789012", AccountName: "TestAccount", EmailAddress: "admin@example.com"},
		},
	})
	setup.Server.SSO.QueueListAccountRoles(awsmock.ListAccountRolesResponse{
		RoleList: []awsmock.RoleInfo{
			{AccountID: "123456789012", RoleName: "BaseRole"},
			{AccountID: "123456789012", RoleName: "TargetRole"},
		},
	})
	_, _, err := setup.Settings.Cache.Refresh(AwsSSO, setup.SSOConf, setup.SSOName, 1, setup.Settings)
	require.NoError(t, err)
	require.NoError(t, setup.Settings.Cache.Save(false))

	// GetRoleCredentials(BaseRole) → AssumeRole(TargetRole).
	setup.Server.SSO.QueueGetRoleCredentials(awsmock.GetRoleCredentialsResponse{
		RoleCredentials: awsmock.RoleCredentials{
			AccessKeyID:     "AKID-BASE",
			SecretAccessKey: "SECRET-BASE",
			SessionToken:    "TOKEN-BASE",
			Expiration:      time.Now().Add(1 * time.Hour).UnixMilli(),
		},
	})
	setup.Server.STS.QueueAssumeRole(awsmock.AssumeRoleResult{
		AccessKeyID:     "AKID-TARGET",
		SecretAccessKey: "SECRET-TARGET",
		SessionToken:    "TOKEN-TARGET",
		Expiration:      time.Now().Add(1 * time.Hour),
		RoleARN:         "arn:aws:iam::123456789012:role/TargetRole",
		SessionName:     "BaseRole@123456789012",
	})

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Eval = EvalCmd{
		AccountId: AccountID(123456789012),
		Role:      "TargetRole",
	}

	output := captureStdout(func() {
		err := (&EvalCmd{}).Run(ctx)
		require.NoError(t, err)
	})

	assert.Contains(t, output, `export AWS_ACCESS_KEY_ID="AKID-TARGET"`)
	assert.Contains(t, output, `export AWS_SECRET_ACCESS_KEY="SECRET-TARGET"`)
	assert.Contains(t, output, `export AWS_SESSION_TOKEN="TOKEN-TARGET"`)
}

// TestE2EMultipleSSO_Selection verifies that commands respect both explicit
// --sso flag overrides and the DefaultSSO setting when multiple SSO instances
// are configured.
func TestE2EMultipleSSO_Selection(t *testing.T) {
	t.Run("explicit_sso_flag_overrides_default", func(t *testing.T) {
		// Config has DefaultSSO=Default; we override with --sso Secondary.
		setup := newE2ESetupMultiSSO(t, "Default")

		// Switch AwsSSO to the Secondary instance so API calls go to the right mock.
		secondaryConf, err := setup.Settings.GetSelectedSSO("Secondary")
		require.NoError(t, err)
		AwsSSO = ssoauth.NewAWSSSOForTest(secondaryConf, setup.Store, setup.Server.URL())
		setup.SSOConf = secondaryConf
		setup.SSOName = "Secondary"
		setup.Settings.Cache.SetSSOName("Secondary")

		preAuth(t, setup)
		populateCache(t, setup)
		queueRoleCredentials(setup.Server)

		t.Setenv("SHELL", "/bin/bash")
		ctx := newRunContext(setup, AUTH_REQUIRED)
		ctx.Cli.SSO = "Secondary"
		ctx.Cli.Eval = EvalCmd{
			AccountId: AccountID(123456789012),
			Role:      "ReadOnly",
		}

		output := captureStdout(func() {
			err := (&EvalCmd{}).Run(ctx)
			require.NoError(t, err)
		})

		assert.Contains(t, output, "AWS_ACCESS_KEY_ID",
			"eval should succeed using Secondary SSO via --sso flag")

		// Default SSO should have no token — it was never authenticated.
		defaultConf, _ := setup.Settings.GetSelectedSSO("Default")
		defaultKey := ssoauth.NewAWSSSOForTest(defaultConf, setup.Store, setup.Server.URL()).StoreKey()
		var defaultToken storage.CreateTokenResponse
		assert.Error(t, setup.Store.GetCreateTokenResponse(defaultKey, &defaultToken),
			"Default SSO should not have been authenticated")
	})

	t.Run("default_sso_from_config_is_used", func(t *testing.T) {
		// Config has DefaultSSO=Secondary; leave ctx.Cli.SSO empty.
		setup := newE2ESetupMultiSSO(t, "Secondary")
		// newE2ESetupMultiSSO with "Secondary" creates AwsSSO for Secondary already.

		preAuth(t, setup)
		populateCache(t, setup)
		queueRoleCredentials(setup.Server)

		t.Setenv("SHELL", "/bin/bash")
		ctx := newRunContext(setup, AUTH_REQUIRED)
		// ctx.Cli.SSO is intentionally left empty — DefaultSSO from config applies.
		ctx.Cli.Eval = EvalCmd{
			AccountId: AccountID(123456789012),
			Role:      "ReadOnly",
		}

		output := captureStdout(func() {
			err := (&EvalCmd{}).Run(ctx)
			require.NoError(t, err)
		})

		assert.Contains(t, output, "AWS_ACCESS_KEY_ID",
			"eval should succeed using Secondary SSO from DefaultSSO config")
		assert.Contains(t, output, "AKIDTEST12345",
			"credentials should come from the Secondary SSO mock")
	})
}

// TestE2EEvalRegion_DefaultNoOverwrite verifies that eval does NOT emit region exports
// when $AWS_DEFAULT_REGION is already set to a user-defined value not managed by aws-sso.
// The default behaviour must leave the user's region untouched.
func TestE2EEvalRegion_DefaultNoOverwrite(t *testing.T) {
	t.Setenv("SHELL", "/bin/bash")
	t.Setenv("AWS_DEFAULT_REGION", "eu-west-1") // user-set; not tracked by aws-sso
	t.Setenv("AWS_SSO_DEFAULT_REGION", "")      // sentinel absent → region is unmanaged

	setup := newE2ESetupWithRegion(t, "us-east-1")
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Eval = EvalCmd{
		AccountId: AccountID(123456789012),
		Role:      "ReadOnly",
	}

	output := captureStdout(func() {
		err := (&EvalCmd{}).Run(ctx)
		require.NoError(t, err)
	})

	// eval must not emit region assignments because the user already has a region set.
	assert.NotContains(t, output, "export AWS_DEFAULT_REGION=",
		"eval must not override a user-set AWS_DEFAULT_REGION without --overwrite-env")
	assert.NotContains(t, output, `export AWS_REGION="`,
		"eval must not override a user-set AWS_REGION without --overwrite-env")
}

// TestE2EEvalRegion_OverwriteRegion verifies that --overwrite-env causes eval to emit
// region exports from config.yaml even when $AWS_DEFAULT_REGION is already set by the user.
func TestE2EEvalRegion_OverwriteRegion(t *testing.T) {
	t.Setenv("SHELL", "/bin/bash")
	t.Setenv("AWS_DEFAULT_REGION", "eu-west-1") // user-set region that should be overridden
	t.Setenv("AWS_SSO_DEFAULT_REGION", "")

	setup := newE2ESetupWithRegion(t, "us-east-1")
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Eval = EvalCmd{
		AccountId:       AccountID(123456789012),
		Role:            "ReadOnly",
		OverwriteRegion: true,
	}

	output := captureStdout(func() {
		err := (&EvalCmd{}).Run(ctx)
		require.NoError(t, err)
	})

	// --overwrite-region must force eval to emit the configured region.
	assert.Contains(t, output, `export AWS_DEFAULT_REGION="us-east-1"`,
		"eval --overwrite-regio must export the configured AWS_DEFAULT_REGION")
	assert.Contains(t, output, `export AWS_REGION="us-east-1"`,
		"eval --overwrite-region must export the configured AWS_REGION")
}

// TestE2EEvalClear exercises the eval --clear path (unsetEnvVars) for both
// managed and unmanaged region states.
func TestE2EEvalClear(t *testing.T) {
	t.Setenv("SHELL", "/bin/bash")

	t.Run("managed_region_is_cleared", func(t *testing.T) {
		// When AWS_DEFAULT_REGION == AWS_SSO_DEFAULT_REGION the region is managed
		// by aws-sso and --clear must emit unset for all three region vars.
		t.Setenv("AWS_DEFAULT_REGION", "us-east-1")
		t.Setenv("AWS_SSO_DEFAULT_REGION", "us-east-1")

		setup := newE2ESetup(t)
		ctx := newRunContext(setup, AUTH_SKIP)
		ctx.Cli.Eval = EvalCmd{Clear: true}

		output := captureStdout(func() {
			err := (&EvalCmd{}).Run(ctx)
			require.NoError(t, err)
		})

		assert.Contains(t, output, "unset AWS_ACCESS_KEY_ID")
		assert.Contains(t, output, "unset AWS_SECRET_ACCESS_KEY")
		assert.Contains(t, output, "unset AWS_SESSION_TOKEN")
		assert.Contains(t, output, "unset AWS_DEFAULT_REGION",
			"managed region should be cleared when AWS_DEFAULT_REGION == AWS_SSO_DEFAULT_REGION")
		assert.Contains(t, output, "unset AWS_SSO_DEFAULT_REGION")
	})

	t.Run("unmanaged_region_is_not_cleared", func(t *testing.T) {
		// When AWS_DEFAULT_REGION != AWS_SSO_DEFAULT_REGION the region was set by
		// the user, not aws-sso; --clear must not emit unset for AWS_DEFAULT_REGION.
		t.Setenv("AWS_DEFAULT_REGION", "eu-west-1")
		t.Setenv("AWS_SSO_DEFAULT_REGION", "us-east-1")

		setup := newE2ESetup(t)
		ctx := newRunContext(setup, AUTH_SKIP)
		ctx.Cli.Eval = EvalCmd{Clear: true}

		output := captureStdout(func() {
			err := (&EvalCmd{}).Run(ctx)
			require.NoError(t, err)
		})

		assert.Contains(t, output, "unset AWS_ACCESS_KEY_ID")
		assert.NotContains(t, output, "unset AWS_DEFAULT_REGION",
			"unmanaged region must not be cleared when AWS_DEFAULT_REGION != AWS_SSO_DEFAULT_REGION")
		assert.Contains(t, output, "unset AWS_SSO_DEFAULT_REGION",
			"sentinel tracking variable should always be cleared")
	})
}

// TestE2EEvalNoArgs verifies that eval returns an error when no role-selection
// flag (--arn, --account+--role, --profile, --refresh, --clear) is provided.
func TestE2EEvalNoArgs(t *testing.T) {
	t.Setenv("SHELL", "/bin/bash")

	setup := newE2ESetup(t)
	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Eval = EvalCmd{} // all zero values

	err := (&EvalCmd{}).Run(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "please specify")
}

// TestE2EEvalByArn verifies that eval selects the role via --arn and emits
// the expected credential export statements.
func TestE2EEvalByArn(t *testing.T) {
	t.Setenv("SHELL", "/bin/bash")

	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Eval = EvalCmd{
		Arn: "arn:aws:iam::123456789012:role/ReadOnly",
	}

	output := captureStdout(func() {
		err := (&EvalCmd{}).Run(ctx)
		require.NoError(t, err)
	})

	assert.Contains(t, output, `export AWS_ACCESS_KEY_ID="AKIDTEST12345"`)
	assert.Contains(t, output, `export AWS_SECRET_ACCESS_KEY="SECRETTEST12345"`)
	assert.Contains(t, output, `export AWS_SESSION_TOKEN="TOKENTEST12345"`)
}

// TestE2EEvalRefresh verifies that eval --refresh reads the role from
// AWS_SSO_ROLE_ARN (EnvArn) and fetches fresh credentials.
func TestE2EEvalRefresh(t *testing.T) {
	t.Setenv("SHELL", "/bin/bash")

	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Eval = EvalCmd{
		Refresh: true,
		EnvArn:  "arn:aws:iam::123456789012:role/ReadOnly",
	}

	output := captureStdout(func() {
		err := (&EvalCmd{}).Run(ctx)
		require.NoError(t, err)
	})

	assert.Contains(t, output, `export AWS_ACCESS_KEY_ID="AKIDTEST12345"`)
	assert.Contains(t, output, `export AWS_SECRET_ACCESS_KEY="SECRETTEST12345"`)
	assert.Contains(t, output, `export AWS_SESSION_TOKEN="TOKENTEST12345"`)
}

// TestE2EEvalRefresh_NoArn verifies that eval --refresh returns an error when
// the AWS_SSO_ROLE_ARN env var is absent (EnvArn is empty).
func TestE2EEvalRefresh_NoArn(t *testing.T) {
	t.Setenv("SHELL", "/bin/bash")

	setup := newE2ESetup(t)
	preAuth(t, setup)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	ctx.Cli.Eval = EvalCmd{
		Refresh: true,
		// EnvArn intentionally empty — simulates missing AWS_SSO_ROLE_ARN
	}

	err := (&EvalCmd{}).Run(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to determine current IAM role")
}

// TestE2EEvalByProfile verifies that eval --profile resolves the role via the
// profile name generated by ProfileFormat and emits credential exports.
func TestE2EEvalByProfile(t *testing.T) {
	t.Setenv("SHELL", "/bin/bash")

	setup := newE2ESetup(t)
	preAuth(t, setup)
	populateCache(t, setup)
	queueRoleCredentials(setup.Server)

	ctx := newRunContext(setup, AUTH_REQUIRED)
	// ProfileFormat "{{.AccountIdPad}}:{{.RoleName}}" → "123456789012:ReadOnly"
	ctx.Cli.Eval = EvalCmd{
		Profile: "123456789012:ReadOnly",
	}

	output := captureStdout(func() {
		err := (&EvalCmd{}).Run(ctx)
		require.NoError(t, err)
	})

	assert.Contains(t, output, `export AWS_ACCESS_KEY_ID="AKIDTEST12345"`)
	assert.Contains(t, output, `export AWS_SECRET_ACCESS_KEY="SECRETTEST12345"`)
	assert.Contains(t, output, `export AWS_SESSION_TOKEN="TOKENTEST12345"`)
}

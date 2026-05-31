package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// unsetEnvForTest unsets key for the duration of the test, restoring it afterward.
func unsetEnvForTest(t *testing.T, key string) {
	t.Helper()
	prev, had := os.LookupEnv(key)
	os.Unsetenv(key) //nolint:errcheck
	t.Cleanup(func() {
		if had {
			os.Setenv(key, prev) //nolint:errcheck
		} else {
			os.Unsetenv(key) //nolint:errcheck
		}
	})
}

func TestSetRegionVars(t *testing.T) {
	t.Run("sets AWS_DEFAULT_REGION, AWS_REGION and sentinel when region is non-empty", func(t *testing.T) {
		shellVars := map[string]string{}
		setRegionVars(shellVars, "us-east-1")
		assert.Equal(t, "us-east-1", shellVars["AWS_DEFAULT_REGION"])
		assert.Equal(t, "us-east-1", shellVars["AWS_REGION"])
		assert.Equal(t, "us-east-1", shellVars["AWS_SSO_DEFAULT_REGION"])
	})

	t.Run("clears sentinel and leaves region vars absent when region is empty", func(t *testing.T) {
		shellVars := map[string]string{}
		setRegionVars(shellVars, "")
		assert.NotContains(t, shellVars, "AWS_DEFAULT_REGION")
		assert.NotContains(t, shellVars, "AWS_REGION")
		assert.Equal(t, "", shellVars["AWS_SSO_DEFAULT_REGION"])
	})
}

func TestIsBashLike(t *testing.T) {
	tests := []struct {
		name  string
		shell string
		want  bool
	}{
		{"bash full path", "/bin/bash", true},
		{"zsh full path", "/usr/local/bin/zsh", true},
		{"fish full path", "/usr/bin/fish", true},
		{"sh full path", "/bin/sh", true},
		{"windows bash.exe", `C:\Program Files\Git\bin\bash.exe`, true},
		{"windows zsh.exe", `C:\tools\zsh.exe`, true},
		{"empty SHELL", "", false},
		{"unsupported csh", "/bin/csh", false},
		{"unsupported ksh", "/bin/ksh", false},
		{"partial match not suffix", "/usr/local/bash-extra/tool", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SHELL", tt.shell)
			assert.Equal(t, tt.want, isBashLike())
		})
	}
}

func TestRegionEnvVarsToUnset(t *testing.T) {
	tests := []struct {
		name             string
		noRegion         bool
		awsDefaultRegion string
		awsRegion        string
		ssoDefaultRegion string
		want             []string
	}{
		{
			name:             "no-region false, default matches sentinel: clear all three",
			noRegion:         false,
			awsDefaultRegion: "us-east-1",
			awsRegion:        "us-east-1",
			ssoDefaultRegion: "us-east-1",
			want:             []string{"AWS_DEFAULT_REGION", "AWS_REGION", "AWS_SSO_DEFAULT_REGION"},
		},
		{
			name:             "no-region false, default does not match sentinel: clear only sentinel",
			noRegion:         false,
			awsDefaultRegion: "us-west-2",
			awsRegion:        "us-east-1",
			ssoDefaultRegion: "us-east-1",
			want:             []string{"AWS_SSO_DEFAULT_REGION"},
		},
		{
			name:             "no-region true, default matches sentinel but aws region differs: clear only sentinel",
			noRegion:         true,
			awsDefaultRegion: "us-east-1",
			awsRegion:        "us-west-2",
			ssoDefaultRegion: "us-east-1",
			want:             []string{"AWS_SSO_DEFAULT_REGION"},
		},
		{
			name:             "no-region true, all match: clear nothing",
			noRegion:         true,
			awsDefaultRegion: "us-east-1",
			awsRegion:        "us-east-1",
			ssoDefaultRegion: "us-east-1",
			want:             []string{},
		},
		{
			name:             "no-region true, default does not match sentinel: clear only sentinel",
			noRegion:         true,
			awsDefaultRegion: "us-west-2",
			awsRegion:        "us-east-1",
			ssoDefaultRegion: "us-east-1",
			want:             []string{"AWS_SSO_DEFAULT_REGION"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := regionEnvVarsToUnset(tt.noRegion, tt.awsDefaultRegion, tt.awsRegion, tt.ssoDefaultRegion)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCheckAwsEnvironment(t *testing.T) {
	// Ensure none of the conflicting vars are set at the start of each subtest.
	conflicting := []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE"}

	t.Run("no conflicting vars: no error", func(t *testing.T) {
		for _, v := range conflicting {
			unsetEnvForTest(t, v)
		}
		assert.NoError(t, checkAwsEnvironment())
	})

	t.Run("AWS_ACCESS_KEY_ID set: error", func(t *testing.T) {
		for _, v := range conflicting {
			unsetEnvForTest(t, v)
		}
		t.Setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
		err := checkAwsEnvironment()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "AWS_ACCESS_KEY_ID")
	})

	t.Run("AWS_SECRET_ACCESS_KEY set: error", func(t *testing.T) {
		for _, v := range conflicting {
			unsetEnvForTest(t, v)
		}
		t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
		err := checkAwsEnvironment()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "AWS_SECRET_ACCESS_KEY")
	})

	t.Run("AWS_PROFILE set: error", func(t *testing.T) {
		for _, v := range conflicting {
			unsetEnvForTest(t, v)
		}
		t.Setenv("AWS_PROFILE", "myprofile")
		err := checkAwsEnvironment()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "AWS_PROFILE")
	})
}

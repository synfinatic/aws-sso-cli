package ecs

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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isolateHome points $HOME at a scratch directory containing an XDG-style
// ~/.config/aws-sso, and clears XDG_CONFIG_HOME so config.ConfigDir resolves
// deterministically regardless of the developer's own environment.  Returns
// the fake home.
func isolateHome(t *testing.T) string {
	t.Helper()

	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".config", "aws-sso"), 0700))
	t.Setenv("HOME", home)
	if _, ok := os.LookupEnv("XDG_CONFIG_HOME"); ok {
		require.NoError(t, os.Unsetenv("XDG_CONFIG_HOME"))
	}
	return home
}

func TestHostPathsDefault(t *testing.T) {
	home := isolateHome(t)
	ecsDir := filepath.Join(home, ".config", "aws-sso", "ecs")

	assert.Equal(t, ecsDir, HostMountPoint(""))
	assert.Equal(t, filepath.Join(ecsDir, SECURITY_FILE_NAME), HostSecurityFilePath(""))
	assert.Equal(t, filepath.Join(ecsDir, BEARER_TOKEN_FILE_NAME), HostBearerTokenPath(""))

	// a pre-existing legacy config directory wins over the XDG location, the
	// same way it does for the config file, JSON store, and cache
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".aws-sso"), 0700))
	assert.Equal(t, filepath.Join(home, ".aws-sso", "ecs"), HostMountPoint(""))
}

func TestHostPathsOverride(t *testing.T) {
	home := isolateHome(t)
	cwd, err := os.Getwd()
	require.NoError(t, err)

	tests := []struct {
		name string
		dir  string
		want string
	}{
		{
			name: "absolute path is used as-is",
			dir:  filepath.Join(home, "secrets"),
			want: filepath.Join(home, "secrets"),
		},
		{
			name: "tilde is expanded",
			dir:  "~/secrets",
			want: filepath.Join(home, "secrets"),
		},
		{
			// docker bind mounts require an absolute source, so a relative
			// --secrets-dir has to be resolved against the working directory
			// rather than passed through
			name: "relative path is made absolute",
			dir:  "secrets/ecs",
			want: filepath.Join(cwd, "secrets", "ecs"),
		},
		{
			name: "trailing separator is normalized away",
			dir:  filepath.Join(home, "secrets") + string(os.PathSeparator),
			want: filepath.Join(home, "secrets"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, HostMountPoint(tt.dir))
			assert.Equal(t, filepath.Join(tt.want, SECURITY_FILE_NAME), HostSecurityFilePath(tt.dir))
			assert.Equal(t, filepath.Join(tt.want, BEARER_TOKEN_FILE_NAME), HostBearerTokenPath(tt.dir))
		})
	}
}

func TestWriteBearerTokenFile(t *testing.T) {
	// an explicit --secrets-dir needs no $HOME isolation: the directory *is*
	// the seam
	dir := filepath.Join(t.TempDir(), "secrets")
	path := HostBearerTokenPath(dir)

	require.NoError(t, WriteBearerTokenFile(dir, "s3cr3t"))

	// The SDKs send the file's contents verbatim as the Authorization header:
	// the "Bearer " prefix must be present and a trailing newline must not be.
	data, err := os.ReadFile(path) // nolint:gosec
	require.NoError(t, err)
	assert.Equal(t, "Bearer s3cr3t", string(data))

	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), fi.Mode().Perm(), "the token is a plaintext secret")

	di, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), di.Mode().Perm())

	// overwriting replaces rather than appends
	require.NoError(t, WriteBearerTokenFile(dir, "other"))
	data, err = os.ReadFile(path) // nolint:gosec
	require.NoError(t, err)
	assert.Equal(t, "Bearer other", string(data))
}

func TestWriteBearerTokenFileEmptyRemoves(t *testing.T) {
	dir := t.TempDir()
	path := HostBearerTokenPath(dir)

	require.NoError(t, WriteBearerTokenFile(dir, "s3cr3t"))
	require.FileExists(t, path)

	require.NoError(t, WriteBearerTokenFile(dir, ""), "an empty token removes the file")
	assert.NoFileExists(t, path)

	assert.NoError(t, WriteBearerTokenFile(dir, ""), "removing an absent file is not an error")
}

func TestWriteBearerTokenFileErrors(t *testing.T) {
	t.Run("directory cannot be created", func(t *testing.T) {
		// a regular file where the secrets directory needs to be
		blocker := filepath.Join(t.TempDir(), "blocker")
		require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))

		err := WriteBearerTokenFile(blocker, "s3cr3t")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to create ECS secrets directory")
	})

	t.Run("file cannot be written", func(t *testing.T) {
		dir := t.TempDir()
		// a directory where the token file needs to be
		require.NoError(t, os.MkdirAll(HostBearerTokenPath(dir), 0700))

		err := WriteBearerTokenFile(dir, "s3cr3t")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to write bearer token file")
	})

	t.Run("file cannot be removed", func(t *testing.T) {
		dir := t.TempDir()
		// a non-empty directory can't be unlinked by os.Remove
		require.NoError(t, os.MkdirAll(HostBearerTokenPath(dir), 0700))
		require.NoError(t, os.WriteFile(filepath.Join(HostBearerTokenPath(dir), "child"), []byte("x"), 0600))

		err := WriteBearerTokenFile(dir, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to remove bearer token file")
	})
}

func TestRemoveLegacySecurityFile(t *testing.T) {
	legacyPaths := func(home string) (dir, file string) {
		return fmt.Sprintf(LEGACY_HOST_MOUNT_POINT_FMT, home), fmt.Sprintf(LEGACY_HOST_NAMED_FILE_FMT, home)
	}

	t.Run("removes the stale file and its now-empty directory", func(t *testing.T) {
		home := isolateHome(t)
		dir, file := legacyPaths(home)
		require.NoError(t, os.MkdirAll(dir, 0700))
		require.NoError(t, os.WriteFile(file, []byte("{}"), 0600))

		RemoveLegacySecurityFile()

		assert.NoFileExists(t, file)
		assert.NoDirExists(t, dir)
	})

	t.Run("leaves a directory that still has other contents", func(t *testing.T) {
		home := isolateHome(t)
		dir, file := legacyPaths(home)
		require.NoError(t, os.MkdirAll(dir, 0700))
		require.NoError(t, os.WriteFile(file, []byte("{}"), 0600))
		other := filepath.Join(dir, "something-else")
		require.NoError(t, os.WriteFile(other, []byte("x"), 0600))

		RemoveLegacySecurityFile()

		assert.NoFileExists(t, file, "the stale secret still goes away")
		assert.FileExists(t, other, "but nothing else in the directory is touched")
	})

	t.Run("no-op when there is nothing to remove", func(t *testing.T) {
		home := isolateHome(t)
		dir, _ := legacyPaths(home)

		assert.NotPanics(t, RemoveLegacySecurityFile)
		assert.NoDirExists(t, dir, "an absent legacy directory is not created")
	})

	t.Run("no-op when HOME is unset", func(t *testing.T) {
		isolateHome(t)
		require.NoError(t, os.Unsetenv("HOME"))

		assert.NotPanics(t, RemoveLegacySecurityFile)
	})
}

func TestOpenHostSecurityFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")

	f, err := OpenHostSecurityFile(dir)
	require.NoError(t, err)
	defer f.Close()

	assert.Equal(t, HostSecurityFilePath(dir), f.Name())

	di, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), di.Mode().Perm(), "created for a plaintext secret")

	fi, err := f.Stat()
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), fi.Mode().Perm())
}

func TestOpenHostSecurityFileErrors(t *testing.T) {
	tests := []struct {
		name string
		// dir returns the --secrets-dir value to open under, given a scratch
		// directory to build it in
		dir func(t *testing.T, scratch string) string
	}{
		{
			name: "directory cannot be created",
			dir: func(t *testing.T, scratch string) string {
				// a regular file standing where the directory would go
				blocker := filepath.Join(scratch, "blocker")
				require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))
				return filepath.Join(blocker, "sub")
			},
		},
		{
			name: "file itself cannot be opened for writing",
			dir: func(t *testing.T, scratch string) string {
				// a directory where the security file needs to be, so the open
				// is what fails rather than the MkdirAll
				require.NoError(t, os.Mkdir(filepath.Join(scratch, SECURITY_FILE_NAME), 0700))
				return scratch
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := OpenHostSecurityFile(tt.dir(t, t.TempDir()))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unable to open security file")
		})
	}
}

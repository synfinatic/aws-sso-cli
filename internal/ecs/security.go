package ecs

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2022 Aaron Turner  <synfinatic at gmail dot com>
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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/synfinatic/aws-sso-cli/internal/config"
	"github.com/synfinatic/aws-sso-cli/internal/fileutils"
	"github.com/synfinatic/aws-sso-cli/internal/logger"
)

const (
	CONTAINER_MOUNT_POINT = "/app/.aws-sso/ecs"
	CONTAINER_NAMED_FILE  = "/app/.aws-sso/ecs/docker-secret.json"

	// ECS_DIR_NAME is the subdirectory of the user's config directory holding
	// the files bind-mounted into the ECS Server container.
	ECS_DIR_NAME = "ecs"
	// SECURITY_FILE_NAME holds the bearer token and SSL cert/key as JSON, read
	// by `ecs server --docker` on startup.
	SECURITY_FILE_NAME = "docker-secret.json"
	// BEARER_TOKEN_FILE_NAME holds just the HTTP Auth header value, for client
	// containers using AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE.
	BEARER_TOKEN_FILE_NAME = "bearer-token"

	// LEGACY_HOST_NAMED_FILE_FMT is where earlier releases wrote the security
	// file: always under the pre-XDG config directory, off a raw $HOME, and
	// named for the bind mount rather than the subsystem.  Nothing reads it
	// anymore; RemoveLegacySecurityFile cleans it up so a stale plaintext
	// secret is not left behind.
	LEGACY_HOST_NAMED_FILE_FMT  = "%s/.aws-sso/mnt/docker-ecs"
	LEGACY_HOST_MOUNT_POINT_FMT = "%s/.aws-sso/mnt"
)

// HostMountPoint returns the host directory bind-mounted into the ECS Server
// container.  An empty dir selects the default: a subdirectory of the user's
// config directory, so XDG users get ~/.config/aws-sso/ecs and users with a
// legacy ~/.aws-sso directory get ~/.aws-sso/ecs -- the same split
// config.ConfigDir already applies to the config file, JSON store, and cache.
//
// Anything else is the user's --secrets-dir.  It is expanded and made absolute
// because docker bind mounts reject a relative source path.
func HostMountPoint(dir string) string {
	if dir == "" {
		return filepath.Join(config.ConfigDir(true), ECS_DIR_NAME)
	}

	path := fileutils.GetHomePath(dir)
	abs, err := filepath.Abs(path)
	if err != nil {
		// only reachable if the working directory is gone; the cleaned path is
		// still the best answer available
		return path
	}
	return abs
}

// HostSecurityFilePath returns the host path of the security file written by
// `ecs docker secrets` / `ecs docker start`.
func HostSecurityFilePath(dir string) string {
	return filepath.Join(HostMountPoint(dir), SECURITY_FILE_NAME)
}

// HostBearerTokenPath returns the host path of the token-only file that client
// containers mount for AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE.
func HostBearerTokenPath(dir string) string {
	return filepath.Join(HostMountPoint(dir), BEARER_TOKEN_FILE_NAME)
}

// RemoveLegacySecurityFile deletes the security file (and its now-empty
// directory) written by earlier releases, so an obsolete copy of the bearer
// token and SSL private key does not linger on disk indefinitely.
func RemoveLegacySecurityFile() {
	home := os.Getenv("HOME")
	if home == "" {
		return
	}

	// gosec flags $HOME as a taint source for these two paths.  Both are fixed
	// literals rooted at it, and os.Remove only ever unlinks the exact path
	// named -- there is no traversal to exploit.
	legacyFile := filepath.Clean(fmt.Sprintf(LEGACY_HOST_NAMED_FILE_FMT, home))
	if err := os.Remove(legacyFile); err != nil { // nolint:gosec
		return // not there, or not ours to remove
	}

	logger.GetLogger().Info("Removed obsolete ECS security file", "path", legacyFile)
	// only succeeds once the directory is empty, which is what we want
	_ = os.Remove(filepath.Clean(fmt.Sprintf(LEGACY_HOST_MOUNT_POINT_FMT, home))) // nolint:gosec
}

type ECSSecurity struct {
	PrivateKey  string `json:"privateKey"` // nolint:gosec
	CertChain   string `json:"certChain"`
	BearerToken string `json:"bearerToken"` // nolint:gosec
}

// WriteBearerTokenFile writes just the HTTP Authorization header value to a
// 0600 file, for client containers that use the AWS SDK's
// AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE instead of the env var form.
//
// The file's contents become the header verbatim -- the SDKs add nothing -- so
// the "Bearer " prefix has to be written here, and no trailing newline: a
// newline is not merely cosmetic, the SDKs reject the token outright rather
// than trimming it, and no request is made at all.  (Verified against
// amazon/aws-cli and aws-sdk-go-v2's endpointcreds provider.)
//
// Passing an empty token removes the file instead.
func WriteBearerTokenFile(dir, bearerToken string) error {
	path := HostBearerTokenPath(dir)

	if bearerToken == "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("unable to remove bearer token file: %w", err)
		}
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("unable to create ECS secrets directory: %w", err)
	}

	header := fmt.Sprintf("Bearer %s", bearerToken)
	if err := os.WriteFile(path, []byte(header), 0600); err != nil {
		return fmt.Errorf("unable to write bearer token file: %w", err)
	}
	return nil
}

// WriteSecurityConfig writes the security configuration to a regular file
// since the ECS container can't read from named pipes when the host is Windows
// or MacOS
func WriteSecurityConfig(f *os.File, privateKey, certChain, bearerToken string) error {
	ecsSecurity := &ECSSecurity{
		PrivateKey:  privateKey,
		CertChain:   certChain,
		BearerToken: bearerToken,
	}

	data, _ := json.Marshal(ecsSecurity)
	_, err := f.Write(data)
	return err
}

// ReadSecurityConfig reads the security configuration from a regular file.
// The file is left in place: the container is not guaranteed to be started by
// aws-sso (docker compose owns its own lifecycle), so it has to survive
// container restarts and recreation rather than being consumed once.
func ReadSecurityConfig(f *os.File) (*ECSSecurity, error) {
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	ecsSecurity := &ECSSecurity{}
	err = json.Unmarshal(data, ecsSecurity)
	if err != nil {
		return nil, err
	}

	return ecsSecurity, nil
}

// TestContainerFilePathOverride replaces the path ContainerSecurityFilePath
// returns.  It is a test seam, exported because it is needed from outside this
// package: the container path is absolute inside the image
// (CONTAINER_NAMED_FILE) and cannot be created on the host, so tests covering
// `ecs server --docker` have nowhere else to point it.  The host side needs no
// such seam -- tests pass a --secrets-dir.  Always restore it to "" when the
// test finishes.
var TestContainerFilePathOverride string = ""

// ContainerSecurityFilePath returns the path the ECS Server reads inside the
// container.
func ContainerSecurityFilePath() string {
	if TestContainerFilePathOverride != "" {
		return TestContainerFilePathOverride
	}
	return CONTAINER_NAMED_FILE
}

// OpenContainerSecurityFile opens the security file for reading from inside the
// ECS Server container.
func OpenContainerSecurityFile() (*os.File, error) {
	f, err := os.Open(ContainerSecurityFilePath())
	if err != nil {
		return nil, fmt.Errorf("unable to open security file: %w", err)
	}
	return f, nil
}

// OpenHostSecurityFile truncates and opens the security file for writing on the
// host, creating dir if needed.  An empty dir selects the default location.
//
// The directory is created 0700 and the file 0600 -- it holds the bearer token
// and the SSL private key in plaintext.  A pre-existing directory keeps
// whatever permissions the user gave it.
func OpenHostSecurityFile(dir string) (*os.File, error) {
	filePath := HostSecurityFilePath(dir)

	if err := os.MkdirAll(filepath.Dir(filePath), 0700); err != nil {
		return nil, fmt.Errorf("unable to open security file: %w", err)
	}

	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("unable to open security file: %w", err)
	}
	return f, nil
}

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
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	dockerclient "github.com/moby/moby/client"
	"github.com/synfinatic/aws-sso-cli/internal/certutil"
	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	ecsclient "github.com/synfinatic/aws-sso-cli/internal/ecs/client"
	// "github.com/davecgh/go-spew/spew"
)

const (
	CONTAINER_NAME = "aws-sso-cli-ecs-server"
)

type EcsDockerCmd struct {
	Start   EcsDockerStartCmd   `kong:"cmd,help='Start the ECS Server in a Docker container'"`
	Stop    EcsDockerStopCmd    `kong:"cmd,help='Stop the ECS Server Docker container'"`
	Secrets EcsDockerSecretsCmd `kong:"cmd,help='Write the bearer token and SSL cert/key files used by Docker Compose or other non-aws-sso launchers'"`
}

type EcsDockerStartCmd struct {
	DisableAuth bool   `kong:"help='Disable HTTP Auth for the ECS Docker Server'"`
	DisableSSL  bool   `kong:"help='Disable SSL/TLS for the ECS Docker Server'"`
	BindIP      string `kong:"help='Host IP address to bind to the ECS Server',default='127.0.0.1'"`
	Port        string `kong:"help='Host port to bind to the ECS Server',default='4144'"`
	Image       string `kong:"help='ECS Server docker image',default='synfinatic/aws-sso-cli-ecs-server'"`
	Version     string `kong:"help='ECS Server docker image version',default='v${VERSION}'"`
	Default     string `kong:"short='d',help='Profile name to load as default credentials on start',predictor='profile'"`
}

// AfterApply determines if SSO auth token is required
func (e EcsDockerStartCmd) AfterApply(runCtx *RunContext) error {
	if e.Default != "" {
		runCtx.Auth = AUTH_REQUIRED
	} else {
		runCtx.Auth = AUTH_SKIP
	}
	return nil
}

func (cc *EcsDockerStartCmd) Run(ctx *RunContext) error {
	// Start the ECS Server in a Docker container
	dockerClient, err := dockerclient.New(dockerclient.FromEnv)
	if err != nil {
		return err
	}

	var privateKey, certChain, bearerToken string

	if !ctx.Cli.Ecs.Docker.Start.DisableSSL {
		privateKey, certChain, err = mintLeafFromStoredCA(ctx)
		if err != nil {
			return err
		}
		if privateKey == "" {
			log.Warn("No CA found in the SecureStore, and --disable-ssl was not passed: " +
				"the ECS Server will refuse to start until you either run " +
				"`aws-sso setup ecs ssl --self-signed`, or pass --disable-ssl here to record that no TLS is intentional.")
		}
	}

	if !ctx.Cli.Ecs.Docker.Start.DisableAuth {
		bearerToken, err = ctx.Store.GetEcsBearerToken()
		if err != nil {
			return err
		}
		if bearerToken == "" {
			log.Warn("No bearer token configured, and --disable-auth was not passed: " +
				"the ECS Server will refuse to start until you either run " +
				"`aws-sso setup ecs auth`, or pass --disable-auth here to record that no HTTP Auth is intentional.")
		}
	}

	image := fmt.Sprintf("%s:%s", ctx.Cli.Ecs.Docker.Start.Image, ctx.Cli.Ecs.Docker.Start.Version)
	_, err = dockerClient.ImageInspect(context.Background(), image)
	if err != nil {
		return fmt.Errorf("failed to find docker image %s. Please pull the image and try again. %s", image, err.Error())
	}

	port, err := network.ParsePort("4144/tcp")
	if err != nil {
		return err
	}
	hostIP, err := netip.ParseAddr(ctx.Cli.Ecs.Docker.Start.BindIP)
	if err != nil {
		return err
	}

	config := &container.Config{
		AttachStdout: true,
		AttachStderr: true,
		Env: []string{
			"AWS_SSO_ECS_PORT=4144",
		},
		Image: image,
		ExposedPorts: network.PortSet{
			port: {},
		},
		User: fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
	}
	if ctx.Cli.LogLevel == "debug" || ctx.Cli.LogLevel == "trace" {
		config.Entrypoint = []string{"./aws-sso", "ecs", "server", "--level", string(ctx.Cli.LogLevel), "--docker"}
	}

	portBinding := network.PortBinding{
		HostIP:   hostIP,
		HostPort: ctx.Cli.Ecs.Docker.Start.Port,
	}

	hostConfig := &container.HostConfig{
		NetworkMode: "bridge",
		PortBindings: network.PortMap{
			port: []network.PortBinding{portBinding},
		},
		// AutoRemove:  true, // not valid for RestartPolicy
		RestartPolicy: container.RestartPolicy{
			Name:              container.RestartPolicyOnFailure,
			MaximumRetryCount: 3, // only valid for on-failure
		},
		Mounts: ecsContainerMounts(ctx.Cli.Ecs.SecretsDir),
	}

	resp, err := dockerClient.ContainerCreate(context.Background(), dockerclient.ContainerCreateOptions{
		Config:     config,
		HostConfig: hostConfig,
		Name:       CONTAINER_NAME,
	})
	if err != nil {
		return err
	}

	// Write security config and close before starting the container so the
	// file is fully flushed to the shared filesystem before the container reads it.
	if err = writeAndCloseSecurityFile(ctx.Cli.Ecs.SecretsDir, privateKey, certChain, bearerToken,
		ctx.Cli.Ecs.Docker.Start.DisableSSL, ctx.Cli.Ecs.Docker.Start.DisableAuth); err != nil {
		_, _ = dockerClient.ContainerRemove(context.Background(), resp.ID, dockerclient.ContainerRemoveOptions{})
		return err
	}

	if _, err = dockerClient.ContainerStart(context.Background(), resp.ID, dockerclient.ContainerStartOptions{}); err != nil {
		// the security file is deliberately left in place: it is durable
		// configuration now, and is just as valid for the next start attempt
		_, _ = dockerClient.ContainerRemove(context.Background(), resp.ID, dockerclient.ContainerRemoveOptions{})
		return err
	}

	if cc.Default != "" {
		// Use http when no cert chain is configured — the server requires both privateKey
		// and certChain to enable TLS; certChain alone is not sufficient.
		proto := "http"
		if !cc.DisableSSL && privateKey != "" && certChain != "" {
			proto = "https"
		}
		serverAddr := fmt.Sprintf("%s:%s", cc.BindIP, cc.Port)

		stopAndRemove := func() {
			_, _ = dockerClient.ContainerStop(context.Background(), resp.ID, dockerclient.ContainerStopOptions{})
			_, _ = dockerClient.ContainerRemove(context.Background(), resp.ID, dockerclient.ContainerRemoveOptions{})
		}

		// Wait until the container is accepting connections (503 = up but no creds yet).
		// Pinning the exact freshly-minted certChain (rather than CA-based trust, as
		// ecs_client_cmd.go's newClient uses) is intentional: this process just minted
		// that exact leaf and already knows it, so there's no ambiguity to resolve via
		// chain verification.
		if err := waitForEcsServerUp(proto, serverAddr, certChain, 30*time.Second); err != nil {
			stopAndRemove()
			return err
		}
		if err := loadProfileToEcsServer(ctx, cc.Default, serverAddr); err != nil {
			stopAndRemove()
			return err
		}
		if err := waitForEcsHealthcheck(proto, serverAddr, certChain, 30*time.Second); err != nil {
			stopAndRemove()
			return err
		}
	}
	return nil
}

type EcsDockerSecretsCmd struct {
	DisableAuth bool `kong:"help='Do not include the HTTP Auth bearer token in the config file'"`
	DisableSSL  bool `kong:"help='Do not include the SSL cert/key in the config file'"`
}

// AfterApply determines if SSO auth token is required
func (e EcsDockerSecretsCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_SKIP
	return nil
}

// Run writes the security config file consumed by the `--docker` entrypoint
// (`ecs.CONTAINER_NAMED_FILE`, bind-mounted from `ecs.HostMountPoint()`) without
// starting or managing a container. This lets tools that own the container lifecycle
// themselves, like `docker compose`, still provision the bearer token / SSL material
// that `EcsDockerStartCmd` would otherwise write just before starting the container.
//
// This is one-time setup, not a per-`docker compose up` ritual: the file persists,
// and re-running is idempotent as far as the certificate goes -- a still-valid leaf
// is reused rather than replaced, so re-running does not invalidate what an already
// running container is serving.
func (cc *EcsDockerSecretsCmd) Run(ctx *RunContext) error {
	var privateKey, certChain, bearerToken string
	var err error

	secretsDir := ctx.Cli.Ecs.SecretsDir

	if !cc.DisableSSL {
		caCert, caErr := ctx.Store.GetEcsCaCert()
		if caErr != nil {
			return caErr
		}
		if privateKey, certChain = reusablePersistedLeaf(secretsDir, caCert); privateKey == "" {
			if privateKey, certChain, err = mintLeafFromStoredCA(ctx); err != nil {
				return err
			}
		}
		if privateKey == "" {
			log.Warn("No CA found in the SecureStore, and --disable-ssl was not passed: " +
				"the ECS Server will refuse to start until you either run " +
				"`aws-sso setup ecs ssl --self-signed`, or pass --disable-ssl here to record that no TLS is intentional.")
		}
	}

	if !cc.DisableAuth {
		if bearerToken, err = ctx.Store.GetEcsBearerToken(); err != nil {
			return err
		}
		if bearerToken == "" {
			log.Warn("No bearer token configured, and --disable-auth was not passed: " +
				"the ECS Server will refuse to start until you either run " +
				"`aws-sso setup ecs auth`, or pass --disable-auth here to record that no HTTP Auth is intentional.")
		}
	}

	if err = writeAndCloseSecurityFile(secretsDir, privateKey, certChain, bearerToken, cc.DisableSSL, cc.DisableAuth); err != nil {
		return err
	}

	log.Info("Wrote ECS security config", "path", ecs.HostSecurityFilePath(secretsDir))
	if bearerToken != "" {
		log.Info("Wrote ECS bearer token file for AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
			"path", ecs.HostBearerTokenPath(secretsDir))
	}
	// docker compose cannot work out ConfigDir()'s XDG-vs-legacy split on its
	// own, so name the directory it has to bind-mount explicitly
	log.Info("Bind-mount this directory into the ECS Server container", "dir", ecs.HostMountPoint(secretsDir))
	return nil
}

// ecsContainerMounts returns the bind mount that gives the ECS Server container
// its security file.  Split out of EcsDockerStartCmd.Run, which needs a live
// Docker daemon, so the --secrets-dir wiring is testable on its own.
func ecsContainerMounts(secretsDir string) []mount.Mount {
	return []mount.Mount{
		{
			Type: mount.TypeBind,
			// the server only reads the security config; it used to delete
			// it after reading, but the file is durable configuration now
			ReadOnly: true,
			Source:   ecs.HostMountPoint(secretsDir),
			Target:   ecs.CONTAINER_MOUNT_POINT,
		},
	}
}

// reusablePersistedLeaf returns the leaf already in the ECS security file when it
// is still fresh and still chains to caCert, so re-running `ecs docker secrets`
// does not churn a new certificate -- and does not leave the file disagreeing
// with what a running container is already serving.  Returns empty
// strings whenever there is nothing safely reusable: no file, no SSL material, an
// unparseable or aging leaf, or a leaf orphaned by a CA rotation.
func reusablePersistedLeaf(secretsDir, caCert string) (privateKey, certChain string) {
	if caCert == "" {
		return "", ""
	}

	f, err := os.Open(ecs.HostSecurityFilePath(secretsDir)) // nolint:gosec
	if err != nil {
		return "", ""
	}
	creds, err := ecs.ReadSecurityConfig(f)
	f.Close()
	if err != nil || creds.PrivateKey == "" || creds.CertChain == "" {
		return "", ""
	}

	notAfter, err := certutil.NotAfter(creds.CertChain)
	if err != nil || time.Until(notAfter) <= leafRefreshThreshold {
		return "", "" // unparseable, or aged enough that we should mint a fresh one
	}
	if err = certutil.VerifyLeafAgainstCA(creds.CertChain, caCert); err != nil {
		return "", "" // the CA was rotated; this leaf is no longer trusted
	}

	return creds.PrivateKey, creds.CertChain
}

// leafRefreshThreshold is how much of certutil.LeafValidity must remain before
// refreshDockerSecurityFileIfStale leaves a persisted leaf alone.  Re-minting
// once a third of its life has elapsed keeps the certificate comfortably fresh
// without rewriting the file on every single command.
const leafRefreshThreshold = certutil.LeafValidity * 2 / 3

// refreshDockerSecurityFileIfStale re-mints the leaf certificate inside an
// existing ECS security file once it has aged past leafRefreshThreshold.
//
// The security file persists -- docker compose owns the container lifecycle, so
// the file has to survive restarts and recreation -- which means the leaf inside
// it ages, unlike the native `ecs server` path where a fresh leaf is minted on
// every start.  Rather than lengthening certutil.LeafValidity to compensate, the
// host-side ECS commands top it up opportunistically: users run `ecs
// load`/`list`/`profile` far more often than every 30 days, so in practice the
// persisted leaf never approaches expiry.
//
// This never creates the file -- only `ecs docker secrets` and `ecs docker
// start` do -- so it is a no-op for anyone not running the server in Docker.
// Errors are logged and swallowed: this is background maintenance on commands
// whose real job is something else.
func refreshDockerSecurityFileIfStale(ctx *RunContext) {
	if ctx.Store == nil {
		return // no SecureStore loaded, so no CA to mint from
	}

	secretsDir := ctx.Cli.Ecs.SecretsDir
	path := ecs.HostSecurityFilePath(secretsDir)
	f, err := os.Open(path) // nolint:gosec
	if err != nil {
		return // no security file: nothing to maintain
	}
	creds, err := ecs.ReadSecurityConfig(f)
	f.Close()
	if err != nil {
		log.Debug("Unable to parse the ECS security config; leaving it alone",
			"path", path, "error", err.Error())
		return
	}

	if creds.PrivateKey == "" || creds.CertChain == "" {
		return // SSL is not in use here
	}

	notAfter, err := certutil.NotAfter(creds.CertChain)
	if err != nil || time.Until(notAfter) > leafRefreshThreshold {
		return // unparseable, or still fresh enough to leave alone
	}

	privateKey, certChain, err := mintLeafFromStoredCA(ctx)
	if err != nil {
		log.Warn("Unable to refresh the ECS Server certificate", "error", err.Error())
		return
	}
	if privateKey == "" || certChain == "" {
		return // the CA has since been removed from the SecureStore
	}

	if err = writeAndCloseSecurityFile(secretsDir, privateKey, certChain, creds.BearerToken,
		creds.DisableSSL, creds.DisableAuth); err != nil {
		log.Warn("Unable to write the refreshed ECS security config", "error", err.Error())
		return
	}

	log.Info("Refreshed the ECS Server certificate; restart the container to use it", "path", path)
}

// mintLeafFromStoredCA fetches the persisted CA from the store and mints a
// fresh, short-lived leaf from it -- the leaf itself is never persisted, so
// this runs host-side right before every `ecs docker start`/`secrets`
// invocation, mirroring the equivalent mint in EcsServerCmd.Run's native path.
func mintLeafFromStoredCA(ctx *RunContext) (privateKey, certChain string, err error) {
	caCert, err := ctx.Store.GetEcsCaCert()
	if err != nil {
		return "", "", err
	}
	caKey, err := ctx.Store.GetEcsCaKey()
	if err != nil {
		return "", "", err
	}
	if caCert == "" || caKey == "" {
		return "", "", nil
	}

	// Clone before use: SecureStorage backends return their cached key string
	// directly, sharing its backing array. ZeroSecret-ing that shared array in
	// place would corrupt the store's own in-memory copy (and, on JsonStore,
	// risk persisting a zeroed CA key to disk on a later save) instead of just
	// scrubbing our local, single-use copy.
	caKey = strings.Clone(caKey)
	leaf, err := certutil.GenerateLeaf(certutil.KeyPair{CertPEM: caCert, KeyPEM: caKey})
	certutil.ZeroSecret(caKey)
	if err != nil {
		return "", "", fmt.Errorf("unable to generate leaf certificate: %w", err)
	}
	return leaf.KeyPEM, leaf.CertPEM, nil
}

// writeAndCloseSecurityFile writes the ECS security config and closes the file
// synchronously before the container starts, ensuring the data is visible on the
// shared filesystem (e.g. VirtioFS) before the container process reads it.
func writeAndCloseSecurityFile(secretsDir, privateKey, certChain, bearerToken string, disableSSL, disableAuth bool) error {
	f, err := ecs.OpenHostSecurityFile(secretsDir)
	if err != nil {
		return err
	}
	if err = ecs.WriteSecurityConfig(f, privateKey, certChain, bearerToken, disableSSL, disableAuth); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}

	// companion file for client containers which read the bearer token via
	// AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE rather than an env var
	if err = ecs.WriteBearerTokenFile(secretsDir, bearerToken); err != nil {
		return err
	}

	ecs.RemoveLegacySecurityFile()
	return nil
}

// waitForEcsHealthcheck polls the ECS server healthcheck endpoint until it returns
// HTTP 200 or the timeout elapses. certChain must be provided when the server uses TLS
// so that the self-signed certificate is trusted.
func waitForEcsHealthcheck(proto, serverAddr, certChain string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	url := fmt.Sprintf("%s://%s%s", proto, serverAddr, ecs.HEALTHCHECK_ROUTE)

	var httpClient *http.Client
	var err error
	if certChain != "" {
		httpClient, err = ecsclient.NewHTTPClient(certChain)
		if err != nil {
			return fmt.Errorf("failed to build TLS client for healthcheck: %w", err)
		}
	} else {
		httpClient = &http.Client{}
	}
	httpClient.Timeout = 2 * time.Second

	for time.Now().Before(deadline) {
		resp, err := httpClient.Get(url) // nolint:gosec,noctx
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("ECS server at %s did not become healthy within %s", serverAddr, timeout)
}

// waitForEcsServerUp polls the ECS server healthcheck endpoint until the server
// responds with any HTTP status code (including 503, which means running but no
// credentials loaded yet) or the timeout elapses. Connection errors are retried.
func waitForEcsServerUp(proto, serverAddr, certChain string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	url := fmt.Sprintf("%s://%s%s", proto, serverAddr, ecs.HEALTHCHECK_ROUTE)

	var httpClient *http.Client
	var err error
	if certChain != "" {
		httpClient, err = ecsclient.NewHTTPClient(certChain)
		if err != nil {
			return fmt.Errorf("failed to build TLS client for server-up check: %w", err)
		}
	} else {
		httpClient = &http.Client{}
	}
	httpClient.Timeout = 2 * time.Second

	for time.Now().Before(deadline) {
		resp, err := httpClient.Get(url) // nolint:gosec,noctx
		if err == nil {
			resp.Body.Close()
			return nil // any HTTP response means the server process is up
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("ECS server at %s did not start within %s", serverAddr, timeout)
}

// loadProfileToEcsServer resolves a profile name to credentials and PUTs them
// into the default slot of the running ECS server.
func loadProfileToEcsServer(ctx *RunContext, profileName, serverAddr string) error {
	cache := ctx.Settings.Cache.GetSSO()
	rFlat, err := cache.Roles.GetRoleByProfile(profileName, ctx.Settings)
	if err != nil {
		return fmt.Errorf("profile %q not found: %w", profileName, err)
	}
	creds := GetRoleCredentials(ctx, AwsSSO, false, rFlat.AccountId, rFlat.RoleName)
	if p, err := rFlat.ProfileName(ctx.Settings); err == nil {
		rFlat.Profile = p
	}
	c := newClient(serverAddr, ctx)
	return c.SubmitCreds(creds, rFlat.Profile, false)
}

type EcsDockerStopCmd struct {
	Version string `kong:"help='ECS Server Version',default='latest'"`
}

// AfterApply determines if SSO auth token is required
func (e EcsDockerStopCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_SKIP
	return nil
}

func (cc *EcsDockerStopCmd) Run(ctx *RunContext) error {
	// Stop the ECS Server in a Docker container
	dockerClient, err := dockerclient.New(dockerclient.FromEnv)
	if err != nil {
		return err
	}

	if _, err = dockerClient.ContainerStop(context.Background(), CONTAINER_NAME, dockerclient.ContainerStopOptions{}); err != nil {
		return err
	}

	_, err = dockerClient.ContainerRemove(context.Background(), CONTAINER_NAME, dockerclient.ContainerRemoveOptions{})
	return err
}

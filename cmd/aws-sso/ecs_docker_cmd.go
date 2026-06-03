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
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	dockerclient "github.com/moby/moby/client"
	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	ecsclient "github.com/synfinatic/aws-sso-cli/internal/ecs/client"
	// "github.com/davecgh/go-spew/spew"
)

const (
	CONTAINER_NAME = "aws-sso-cli-ecs-server"
)

type EcsDockerCmd struct {
	Start EcsDockerStartCmd `kong:"cmd,help='Start the ECS Server in a Docker container'"`
	Stop  EcsDockerStopCmd  `kong:"cmd,help='Stop the ECS Server Docker container'"`
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
		privateKey, err = ctx.Store.GetEcsSslKey()
		if err != nil {
			return err
		}
		certChain, err = ctx.Store.GetEcsSslCert()
		if err != nil {
			return err
		}
	}

	if !ctx.Cli.Ecs.Docker.Start.DisableAuth {
		bearerToken, err = ctx.Store.GetEcsBearerToken()
		if err != nil {
			return err
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
		Mounts: []mount.Mount{
			{
				Type:     mount.TypeBind,
				ReadOnly: false,
				Source:   fmt.Sprintf(ecs.HOST_MOUNT_POINT_FMT, os.Getenv("HOME")),
				Target:   ecs.CONTAINER_MOUNT_POINT,
			},
		},
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
	if err = writeAndCloseSecurityFile(privateKey, certChain, bearerToken); err != nil {
		_, _ = dockerClient.ContainerRemove(context.Background(), resp.ID, dockerclient.ContainerRemoveOptions{})
		return err
	}

	if _, err = dockerClient.ContainerStart(context.Background(), resp.ID, dockerclient.ContainerStartOptions{}); err != nil {
		os.Remove(ecs.SecurityFilePath(ecs.WRITE_ONLY)) // clean up on failure
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

// writeAndCloseSecurityFile writes the ECS security config and closes the file
// synchronously before the container starts, ensuring the data is visible on the
// shared filesystem (e.g. VirtioFS) before the container process reads it.
func writeAndCloseSecurityFile(privateKey, certChain, bearerToken string) error {
	f, err := ecs.OpenSecurityFile(ecs.WRITE_ONLY)
	if err != nil {
		return err
	}
	if err = ecs.WriteSecurityConfig(f, privateKey, certChain, bearerToken); err != nil {
		f.Close()
		return err
	}
	return f.Close()
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

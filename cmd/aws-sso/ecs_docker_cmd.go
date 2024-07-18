package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2024 Aaron Turner  <synfinatic at gmail dot com>
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
	"os"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/synfinatic/aws-sso-cli/internal/ecs"
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
	Version     string `kong:"help='ECS Server docker image version',default='${VERSION}'"`
}

// AfterApply determines if SSO auth token is required
func (l EcsDockerStartCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_SKIP
	return nil
}

func (cc *EcsDockerStartCmd) Run(ctx *RunContext) error {
	// Start the ECS Server in a Docker container
	cli, err := client.NewClientWithOpts(client.FromEnv)
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

	config := &container.Config{
		AttachStdout: true,
		AttachStderr: true,
		Env: []string{
			"AWS_SSO_ECS_PORT=4144",
		},
		Image: image,
		ExposedPorts: nat.PortSet{
			nat.Port("4144/tcp"): {},
		},
		User: fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
	}
	if ctx.Cli.LogLevel == "debug" || ctx.Cli.LogLevel == "trace" {
		config.Entrypoint = []string{"./aws-sso", "ecs", "run", "--level", string(ctx.Cli.LogLevel), "--docker"}
	}

	portBinding := nat.PortBinding{
		HostIP:   ctx.Cli.Ecs.Docker.Start.BindIP,
		HostPort: ctx.Cli.Ecs.Docker.Start.Port,
	}

	hostConfig := &container.HostConfig{
		// AutoRemove:  true, // not valid for RestartPolicy
		NetworkMode: "bridge",
		PortBindings: nat.PortMap{
			nat.Port("4144/tcp"): []nat.PortBinding{portBinding},
		},
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

	resp, err := cli.ContainerCreate(context.Background(), config, hostConfig, nil, nil, CONTAINER_NAME)
	if err != nil {
		return err
	}

	// must create the named pipe before we start the container
	f, err := ecs.OpenSecurityFile(ecs.WRITE_ONLY)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = ecs.WriteSecurityConfig(f, privateKey, certChain, bearerToken); err != nil {
		return err
	}

	if err = cli.ContainerStart(context.Background(), resp.ID, container.StartOptions{}); err != nil {
		os.Remove(ecs.SecurityFilePath(ecs.WRITE_ONLY)) // clean up on failure
		return err
	}
	return nil
}

type EcsDockerStopCmd struct {
	Version string `kong:"help='ECS Server Version',default='latest'"`
}

// AfterApply determines if SSO auth token is required
func (l EcsDockerStopCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_SKIP
	return nil
}

func (cc *EcsDockerStopCmd) Run(ctx *RunContext) error {
	// Stop the ECS Server in a Docker container
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return err
	}

	if err = cli.ContainerStop(context.Background(), CONTAINER_NAME, container.StopOptions{}); err != nil {
		return err
	}

	return cli.ContainerRemove(context.Background(), CONTAINER_NAME, container.RemoveOptions{})
}

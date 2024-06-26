package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2023 Aaron Turner  <synfinatic at gmail dot com>
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
	"net"

	// "github.com/davecgh/go-spew/spew"
	"github.com/synfinatic/aws-sso-cli/internal/ecs/server"
)

const (
	ECS_PORT = 4144
)

type EcsCmd struct {
	Run           EcsRunCmd     `kong:"cmd,help='Run the ECS Server'"`
	List          EcsListCmd    `kong:"cmd,help='List profiles loaded in the ECS Server'"`
	Load          EcsLoadCmd    `kong:"cmd,help='Load new IAM Role credentials into the ECS Server'"`
	Unload        EcsUnloadCmd  `kong:"cmd,help='Unload the current IAM Role credentials from the ECS Server'"`
	Profile       EcsProfileCmd `kong:"cmd,help='Get the current role profile name in the default slot'"`
	SecurityToken string        `kong:"help='Security Token to use for authentication',env='AWS_CONTAINER_AUTHORIZATION_TOKEN'"`
}

type EcsRunCmd struct {
	Port int `kong:"help='TCP port to listen on',env='AWS_SSO_ECS_PORT',default=4144"`
}

func (cc *EcsRunCmd) Run(ctx *RunContext) error {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", ctx.Cli.Ecs.Run.Port))
	if err != nil {
		return err
	}
	s, err := server.NewEcsServer(context.TODO(), ctx.Cli.Ecs.SecurityToken, l)
	if err != nil {
		return err
	}
	return s.Serve()
}

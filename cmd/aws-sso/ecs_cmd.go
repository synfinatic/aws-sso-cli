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

// "github.com/davecgh/go-spew/spew"

const (
	ECS_PORT = 4144
)

type EcsCmd struct {
	// SecretsDir is declared here rather than on `ecs docker secrets` so that a
	// single setting covers everything that touches the files: writing them,
	// bind-mounting them in `ecs docker start`, and the opportunistic leaf
	// refresh on the client commands.
	SecretsDir string `kong:"help='Directory holding the ECS Server Docker secrets files (default: <config dir>/ecs)',env='AWS_SSO_ECS_SECRETS_DIR',predictor='directory'"`

	Server  EcsServerCmd  `kong:"cmd,help='Run the ECS Server locally'"`
	Docker  EcsDockerCmd  `kong:"cmd,help='Start the ECS Server in a Docker container'"`
	List    EcsListCmd    `kong:"cmd,help='List profiles loaded in the ECS Server'"`
	Unload  EcsUnloadCmd  `kong:"cmd,help='Unload the current IAM Role credentials from the ECS Server'"`
	Profile EcsProfileCmd `kong:"cmd,help='Get the current role profile name in the default slot'"`
	// login required commands
	Load EcsLoadCmd `kong:"cmd,help='Load new IAM Role credentials into the ECS Server',group='login-required'"`
}

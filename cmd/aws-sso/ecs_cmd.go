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
	"fmt"
	"os"
	"strings"
	// "github.com/davecgh/go-spew/spew"
)

const (
	ECS_PORT = 4144
)

type EcsCmd struct {
	Auth    EcsAuthCmd    `kong:"cmd,help='Manage the ECS Server/AWS Client authentication'"`
	SSL     EcsSSLCmd     `kong:"cmd,help='Manage the ECS Server SSL configuration'"`
	Server  EcsServerCmd  `kong:"cmd,help='Run the ECS Server locally'"`
	Docker  EcsDockerCmd  `kong:"cmd,help='Start the ECS Server in a Docker container'"`
	List    EcsListCmd    `kong:"cmd,help='List profiles loaded in the ECS Server'"`
	Unload  EcsUnloadCmd  `kong:"cmd,help='Unload the current IAM Role credentials from the ECS Server'"`
	Profile EcsProfileCmd `kong:"cmd,help='Get the current role profile name in the default slot'"`
	// login required commands
	Load EcsLoadCmd `kong:"cmd,help='Load new IAM Role credentials into the ECS Server',group='login-required'"`
}

type EcsAuthCmd struct {
	BearerToken string `kong:"short=t,help='Bearer token value to use for ECS Server',xor='flag'"`
	Delete      bool   `kong:"short=d,help='Delete the current bearer token',xor='flag'"`
}

func (cc *EcsAuthCmd) Run(ctx *RunContext) error {
	// Delete the token
	if ctx.Cli.Ecs.Auth.Delete {
		return ctx.Store.DeleteEcsBearerToken()
	}

	// Or store the token in the SecureStore
	if ctx.Cli.Ecs.Auth.BearerToken == "" {
		return fmt.Errorf("no token provided")
	}
	if strings.HasPrefix(ctx.Cli.Ecs.Auth.BearerToken, "Bearer ") {
		return fmt.Errorf("token should not start with 'Bearer '")
	}
	return ctx.Store.SaveEcsBearerToken(ctx.Cli.Ecs.Auth.BearerToken)
}

type EcsSSLCmd struct {
	Delete      bool   `kong:"short=d,help='Disable SSL and delete the current SSL cert/key',xor='flag,cert,key'"`
	Print       bool   `kong:"short=p,help='Print the current SSL certificate',xor='flag,cert,key'"`
	Certificate string `kong:"short=c,type='existingfile',help='Path to certificate chain PEM file',predictor='allFiles',group='add-ssl',xor='cert'"`
	PrivateKey  string `kong:"short=k,type='existingfile',help='Path to private key file PEM file',predictor='allFiles',group='add-ssl',xor='key'"`
	Force       bool   `kong:"hidden,help='Force loading the certificate'"`
}

func (cc *EcsSSLCmd) Run(ctx *RunContext) error {
	if ctx.Cli.Ecs.SSL.Delete {
		return ctx.Store.DeleteEcsSslKeyPair()
	} else if ctx.Cli.Ecs.SSL.Print {
		cert, err := ctx.Store.GetEcsSslCert()
		if err != nil {
			return err
		}
		if cert == "" {
			return fmt.Errorf("no certificate found")
		}
		fmt.Println(cert)
		return nil
	}

	var privateKey, certChain []byte
	var err error

	if !ctx.Cli.Ecs.SSL.Force {
		log.Warn("This feature is experimental and may not work as expected.")
		log.Warn("Please read https://github.com/synfinatic/aws-sso-cli/issues/936 before contiuing.")
		log.Fatal("Use `--force` to continue anyways.")
	}

	certChain, err = os.ReadFile(ctx.Cli.Ecs.SSL.Certificate)
	if err != nil {
		return fmt.Errorf("failed to read certificate chain file: %w", err)
	}

	if ctx.Cli.Ecs.SSL.PrivateKey != "" {
		privateKey, err = os.ReadFile(ctx.Cli.Ecs.SSL.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to read private key file: %w", err)
		}
	}

	return ctx.Store.SaveEcsSslKeyPair(privateKey, certChain)
}

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
	"os"
	"strings"

	// "github.com/davecgh/go-spew/spew"
	"github.com/synfinatic/aws-sso-cli/internal/ecs/server"
)

const (
	ECS_PORT = 4144
)

type EcsCmd struct {
	Run         EcsRunCmd         `kong:"cmd,help='Run the ECS Server'"`
	BearerToken EcsBearerTokenCmd `kong:"cmd,help='Configure the ECS Server/AWS Client bearer token'"`
	Cert        EcsCertCmd        `kong:"cmd,help='Configure the ECS Server SSL certificate'"`
	List        EcsListCmd        `kong:"cmd,help='List profiles loaded in the ECS Server'"`
	Load        EcsLoadCmd        `kong:"cmd,help='Load new IAM Role credentials into the ECS Server'"`
	Unload      EcsUnloadCmd      `kong:"cmd,help='Unload the current IAM Role credentials from the ECS Server'"`
	Profile     EcsProfileCmd     `kong:"cmd,help='Get the current role profile name in the default slot'"`
}

type EcsRunCmd struct {
	Port int `kong:"help='TCP port to listen on',env='AWS_SSO_ECS_PORT',default=4144"`
}

func (cc *EcsRunCmd) Run(ctx *RunContext) error {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", ctx.Cli.Ecs.Run.Port))
	if err != nil {
		return err
	}

	token, err := ctx.Store.GetEcsBearerToken()
	if err != nil {
		return err
	}
	if token == "" {
		log.Warnf("No authentication token set, use 'aws-sso ecs bearer-token' to set one")
	}
	var privateKey, certChain string
	if privateKey, err = ctx.Store.GetEcsSslKey(); err != nil {
		return err
	} else if privateKey != "" {
		// only get the certificate if the private key is set
		certChain, err = ctx.Store.GetEcsSslCert()
		if err != nil {
			return err
		}
		log.Infof("Running ECS Server with SSL/TLS enabled")
	} else {
		log.Infof("Running ECS Server without SSL/TLS")
	}
	s, err := server.NewEcsServer(context.TODO(), token, l, privateKey, certChain)
	if err != nil {
		return err
	}
	return s.Serve()
}

type EcsBearerTokenCmd struct {
	Token  string `kong:"short=t,help='Bearer token value to use for ECS Server',xor='flag'"`
	Delete bool   `kong:"short=d,help='Delete the current bearer token',xor='flag'"`
}

func (cc *EcsBearerTokenCmd) Run(ctx *RunContext) error {
	// Delete the token
	if ctx.Cli.Ecs.BearerToken.Delete {
		return ctx.Store.DeleteEcsBearerToken()
	}

	// Or store the token in the SecureStore
	if ctx.Cli.Ecs.BearerToken.Token == "" {
		return fmt.Errorf("no token provided")
	}
	if !strings.HasPrefix(ctx.Cli.Ecs.BearerToken.Token, "Bearer ") {
		return fmt.Errorf("token should start with 'Bearer '")
	}
	return ctx.Store.SaveEcsBearerToken(ctx.Cli.Ecs.BearerToken.Token)
}

type EcsCertCmd struct {
	CertChain  string `kong:"short=c,type='existingfile',help='Path to certificate chain PEM file',predictor='allFiles',xor='key'"`
	PrivateKey string `kong:"short=p,type='existingfile',help='Path to private key file PEM file',predictor='allFiles',xor='cert'"`
	Delete     bool   `kong:"short=d,help='Delete the current SSL certificate key pair',xor='key,cert'"`
}

func (cc *EcsCertCmd) Run(ctx *RunContext) error {
	// If delete flag is set, delete the key pair
	if ctx.Cli.Ecs.Cert.Delete {
		return ctx.Store.DeleteEcsSslKeyPair()
	}

	if ctx.Cli.Ecs.Cert.CertChain == "" && ctx.Cli.Ecs.Cert.PrivateKey != "" {
		return fmt.Errorf("if --private-key is set, --cert-chain must also be set")
	}

	// Else, save the key pair
	privateKey, err := os.ReadFile(ctx.Cli.Ecs.Cert.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %w", err)
	}

	certChain, err := os.ReadFile(ctx.Cli.Ecs.Cert.CertChain)
	if err != nil {
		return fmt.Errorf("failed to read certificate chain file: %w", err)
	}

	return ctx.Store.SaveEcsSslKeyPair(privateKey, certChain)
}

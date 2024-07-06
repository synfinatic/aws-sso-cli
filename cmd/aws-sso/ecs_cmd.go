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
	"net"
	"os"
	"strings"

	// "github.com/davecgh/go-spew/spew"
	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	"github.com/synfinatic/aws-sso-cli/internal/ecs/server"
)

const (
	ECS_PORT = 4144
)

type EcsCmd struct {
	Run         EcsRunCmd         `kong:"cmd,help='Run the ECS Server locally'"`
	BearerToken EcsBearerTokenCmd `kong:"cmd,help='Configure the ECS Server/AWS Client bearer token'"`
	Docker      EcsDockerCmd      `kong:"cmd,help='Start the ECS Server in a Docker container'"`
	Cert        EcsCertCmd        `kong:"cmd,help='Configure the ECS Server SSL certificate/private key'"`
	List        EcsListCmd        `kong:"cmd,help='List profiles loaded in the ECS Server'"`
	Load        EcsLoadCmd        `kong:"cmd,help='Load new IAM Role credentials into the ECS Server'"`
	Unload      EcsUnloadCmd      `kong:"cmd,help='Unload the current IAM Role credentials from the ECS Server'"`
	Profile     EcsProfileCmd     `kong:"cmd,help='Get the current role profile name in the default slot'"`
}

type EcsRunCmd struct {
	Port int `kong:"help='TCP port to listen on',env='AWS_SSO_ECS_PORT',default=4144"`
	// hidden flags are for internal use only when running in a docker container
	Docker bool `kong:"hidden,help='Enable Docker support for ECS Server'"`
}

func (cc *EcsRunCmd) Run(ctx *RunContext) error {
	// Start the ECS Server
	ip := "127.0.0.1"
	if ctx.Cli.Ecs.Run.Docker {
		ip = "0.0.0.0"
	}
	l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ip, ctx.Cli.Ecs.Run.Port))
	if err != nil {
		return err
	}

	var bearerToken, privateKey, certChain string
	if ctx.Cli.Ecs.Run.Docker {
		// fetch the creds from our temporary file mounted in the docker container
		f, err := ecs.OpenSecurityFile(ecs.READ_ONLY)
		if err != nil {
			log.Warnf("Failed to open ECS credentials file: %s", err.Error())
		} else {
			creds, err := ecs.ReadSecurityConfig(f)
			if err != nil {
				return err
			}
			// have to manually close since defer won't work in this case
			f.Close()
			os.Remove(f.Name())

			bearerToken = creds.BearerToken
			privateKey = creds.PrivateKey
			certChain = creds.CertChain
		}
	} else {
		if bearerToken, err = ctx.Store.GetEcsBearerToken(); err != nil {
			return err
		}

		if privateKey, err = ctx.Store.GetEcsSslKey(); err != nil {
			return err
		} else if privateKey != "" {
			// only get the certificate if the private key is set
			if certChain, err = ctx.Store.GetEcsSslCert(); err != nil {
				return err
			}
		}
	}

	if bearerToken == "" {
		log.Warnf("HTTP Auth: disabled. Use 'aws-sso ecs bearer-token' to enable")
	} else {
		log.Info("HTTP Auth: enabled")
	}

	if privateKey != "" && certChain != "" {
		log.Infof("SSL/TLS: enabled")
	} else {
		log.Warnf("SSL/TLS: disabled.  Use 'aws-sso ecs cert' to enable")
	}

	s, err := server.NewEcsServer(context.TODO(), bearerToken, l, privateKey, certChain)
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
	Load   EcsCertLoadCmd   `kong:"cmd,help='Load a new SSL certificate/private key into the ECS Server'"`
	Delete EcsCertDeleteCmd `kong:"cmd,help='Delete the current SSL certificate/private key'"`
	Print  EcsCertPrintCmd  `kong:"cmd,help='Print the current SSL certificate'"`
}

type EcsCertLoadCmd struct {
	CertChain  string `kong:"short=c,type='existingfile',help='Path to certificate chain PEM file',predictor='allFiles',required"`
	PrivateKey string `kong:"short=p,type='existingfile',help='Path to private key file PEM file',predictor='allFiles'"`
	Force      bool   `kong:"hidden,help='Force loading the certificate'"`
}

type EcsCertDeleteCmd struct{}

func (cc *EcsCertDeleteCmd) Run(ctx *RunContext) error {
	return ctx.Store.DeleteEcsSslKeyPair()
}

type EcsCertPrintCmd struct{}

func (cc *EcsCertPrintCmd) Run(ctx *RunContext) error {
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

func (cc *EcsCertLoadCmd) Run(ctx *RunContext) error {
	var privateKey, certChain []byte
	var err error

	if !ctx.Cli.Ecs.Cert.Load.Force {
		log.Warn("This feature is experimental and may not work as expected.")
		log.Warn("Please read https://github.com/synfinatic/aws-sso-cli/issues/936 before contiuing.")
		log.Fatal("Use `--force` to continue anyways.")
	}

	certChain, err = os.ReadFile(ctx.Cli.Ecs.Cert.Load.CertChain)
	if err != nil {
		return fmt.Errorf("failed to read certificate chain file: %w", err)
	}

	if ctx.Cli.Ecs.Cert.Load.PrivateKey != "" {
		privateKey, err = os.ReadFile(ctx.Cli.Ecs.Cert.Load.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to read private key file: %w", err)
		}
	}

	return ctx.Store.SaveEcsSslKeyPair(privateKey, certChain)
}

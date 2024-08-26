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

	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	"github.com/synfinatic/aws-sso-cli/internal/ecs/server"
)

type EcsServerCmd struct {
	BindIP string `kong:"help='Bind address for ECS Server',default='127.0.0.1'"`
	Port   int    `kong:"help='TCP port to listen on',default=4144"`
	// hidden flags are for internal use only when running in a docker container
	Docker      bool `kong:"hidden"`
	DisableAuth bool `kong:"help='Disable HTTP Auth for the ECS Server'"`
	DisableSSL  bool `kong:"help='Disable SSL/TLS for the ECS Server'"`
}

// AfterApply determines if SSO auth token is required
func (e EcsServerCmd) AfterApply(runCtx *RunContext) error {
	if e.Docker {
		runCtx.Auth = AUTH_NO_CONFIG
	} else {
		runCtx.Auth = AUTH_SKIP
	}
	return nil
}

func (cc *EcsServerCmd) Run(ctx *RunContext) error {
	// Start the ECS Server
	bindIP := ctx.Cli.Ecs.Server.BindIP
	if ctx.Cli.Ecs.Server.Docker {
		// if running in a docker container, bind to all interfaces
		bindIP = "0.0.0.0"
	}
	l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", bindIP, ctx.Cli.Ecs.Server.Port))
	if err != nil {
		return err
	}

	var bearerToken, privateKey, certChain string
	if ctx.Cli.Ecs.Server.Docker {
		// fetch the creds from our temporary file mounted in the docker container
		f, err := ecs.OpenSecurityFile(ecs.READ_ONLY)
		if err != nil {
			log.Warn("Failed to open ECS credentials file", "error", err.Error())
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

	// Disable SSL, even if configure
	if ctx.Cli.Ecs.Server.DisableSSL {
		privateKey = ""
		certChain = ""
	}

	if ctx.Cli.Ecs.Server.DisableAuth {
		bearerToken = ""
	}

	if bearerToken == "" {
		log.Warn("HTTP Auth: disabled. Use 'aws-sso ecs bearer-token' to enable")
	} else {
		log.Info("HTTP Auth: enabled")
	}

	if privateKey != "" && certChain != "" {
		log.Info("SSL/TLS: enabled")
	} else {
		log.Warn("SSL/TLS: disabled.  Use 'aws-sso ecs cert' to enable")
	}

	s, err := server.NewEcsServer(context.TODO(), bearerToken, l, privateKey, certChain)
	if err != nil {
		return err
	}
	return s.Serve()
}

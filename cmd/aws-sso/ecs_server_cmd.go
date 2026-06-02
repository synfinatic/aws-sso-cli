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
	"net"
	"os"

	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	"github.com/synfinatic/aws-sso-cli/internal/ecs/server"
)

type EcsServerCmd struct {
	BindIP  string `kong:"help='Bind address for ECS Server',default='127.0.0.1'"`
	Port    int    `kong:"help='TCP port to listen on',default=4144"`
	Default string `kong:"short='d',help='Profile name to load as default credentials on start',predictor='profile'"`
	// hidden flags are for internal use only when running in a docker container
	Docker      bool `kong:"hidden"`
	DisableAuth bool `kong:"help='Disable HTTP Auth for the ECS Server'"`
	DisableSSL  bool `kong:"help='Disable SSL/TLS for the ECS Server'"`
}

// AfterApply determines if SSO auth token is required
func (e EcsServerCmd) AfterApply(runCtx *RunContext) error {
	if e.Docker {
		runCtx.Auth = AUTH_NO_CONFIG
	} else if e.Default != "" {
		runCtx.Auth = AUTH_REQUIRED
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
			os.Remove(f.Name()) // nolint:gosec

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

	if bearerToken == "" && !ctx.Cli.Ecs.Server.DisableAuth {
		log.Warn("HTTP Auth: disabled. Use 'aws-sso setup ecs auth' to enable")
	} else {
		log.Info("HTTP Auth: enabled")
	}

	if privateKey != "" && certChain != "" {
		log.Info("SSL/TLS: enabled")
	} else if !ctx.Cli.Ecs.Server.DisableSSL {
		log.Warn("SSL/TLS: disabled.  Use 'aws-sso setup ecs ssl' to enable")
	}

	s, err := server.NewEcsServer(context.TODO(), bearerToken, l, privateKey, certChain)
	if err != nil {
		return err
	}
	if cc.Default != "" && !cc.Docker {
		if err := setServerDefaultProfile(ctx, s, cc.Default); err != nil {
			return err
		}
	}
	return s.Serve()
}

// setServerDefaultProfile resolves a profile name to credentials and injects them
// directly into the server's default slot before Serve() is called.
func setServerDefaultProfile(ctx *RunContext, s *server.EcsServer, profileName string) error {
	cache := ctx.Settings.Cache.GetSSO()
	rFlat, err := cache.Roles.GetRoleByProfile(profileName, ctx.Settings)
	if err != nil {
		return fmt.Errorf("profile %q not found: %w", profileName, err)
	}
	creds := GetRoleCredentials(ctx, AwsSSO, false, rFlat.AccountId, rFlat.RoleName)
	if p, err := rFlat.ProfileName(ctx.Settings); err == nil {
		rFlat.Profile = p
	}
	s.DefaultCreds = &ecs.ECSClientRequest{
		Creds:       creds,
		ProfileName: rFlat.Profile,
	}
	return nil
}

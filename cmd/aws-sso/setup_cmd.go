package main

import (
	"fmt"
	"os"
	"strings"
)

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2025 Aaron Turner  <synfinatic at gmail dot com>
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

type SetupCmd struct {
	Completions CompleteCmd      `kong:"cmd,help='Manage shell completions'"`
	Wizard      SetupWizardCmd   `kong:"cmd,help='Run the configuration wizard'"`
	Profiles    SetupProfilesCmd `kong:"cmd,help='Update ~/.aws/config with AWS SSO profiles from the cache'"`
	Ecs         SetupEcsCmd      `kong:"cmd,help='Manage ECS Server secrets'"`
}

type SetupEcsCmd struct {
	Auth EcsAuthCmd `kong:"cmd,help='Configure HTTP Authentication for the ECS Server'"`
	SSL  EcsSSLCmd  `kong:"cmd,help='Load SSL cert/key for the ECS Server'"`
}

type EcsAuthCmd struct {
	BearerToken string `kong:"short=t,help='Bearer token value to use for ECS Server',xor='flag'"`
	Delete      bool   `kong:"short=d,help='Delete the current bearer token',xor='flag'"`
}

// AfterApply determines if SSO auth token is required
func (e EcsAuthCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_SKIP
	return nil
}

func (cc *EcsAuthCmd) Run(ctx *RunContext) error {
	// Delete the token
	if ctx.Cli.Setup.Ecs.Auth.Delete {
		return ctx.Store.DeleteEcsBearerToken()
	}

	// Or store the token in the SecureStore
	if ctx.Cli.Setup.Ecs.Auth.BearerToken == "" {
		return fmt.Errorf("no bearer token provided")
	}
	if strings.HasPrefix(ctx.Cli.Setup.Ecs.Auth.BearerToken, "Bearer ") {
		return fmt.Errorf("token should not start with 'Bearer '")
	}
	return ctx.Store.SaveEcsBearerToken(ctx.Cli.Setup.Ecs.Auth.BearerToken)
}

type EcsSSLCmd struct {
	Delete      bool   `kong:"short=d,help='Disable SSL and delete the current SSL cert/key',xor='flag,cert,key'"`
	Print       bool   `kong:"short=p,help='Print the current SSL certificate',xor='flag,cert,key'"`
	Certificate string `kong:"short=c,type='existingfile',help='Path to certificate chain PEM file',predictor='allFiles',group='add-ssl',xor='cert'"`
	PrivateKey  string `kong:"short=k,type='existingfile',help='Path to private key file PEM file',predictor='allFiles',group='add-ssl',xor='key'"`
	Force       bool   `kong:"hidden,help='Force loading the certificate'"`
}

// AfterApply determines if SSO auth token is required
func (e EcsSSLCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_SKIP
	return nil
}

func (cc *EcsSSLCmd) Run(ctx *RunContext) error {
	if ctx.Cli.Setup.Ecs.SSL.Delete {
		return ctx.Store.DeleteEcsSslKeyPair()
	} else if ctx.Cli.Setup.Ecs.SSL.Print {
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

	if !ctx.Cli.Setup.Ecs.SSL.Force {
		log.Warn("This feature is experimental and may not work as expected.")
		log.Warn("Please read https://github.com/synfinatic/aws-sso-cli/issues/936 before contiuing.")
		log.Fatal("Use `--force` to continue anyways.")
	}

	certChain, err = os.ReadFile(ctx.Cli.Setup.Ecs.SSL.Certificate)
	if err != nil {
		return fmt.Errorf("failed to read certificate chain file: %w", err)
	}

	if ctx.Cli.Setup.Ecs.SSL.PrivateKey != "" {
		privateKey, err = os.ReadFile(ctx.Cli.Setup.Ecs.SSL.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to read private key file: %w", err)
		}
	}

	return ctx.Store.SaveEcsSslKeyPair(privateKey, certChain)
}

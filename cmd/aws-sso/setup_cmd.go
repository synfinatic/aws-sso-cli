package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/synfinatic/aws-sso-cli/internal/certutil"
	"github.com/synfinatic/aws-sso-cli/internal/config"
	"github.com/synfinatic/aws-sso-cli/internal/fileutils"
)

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
	BearerToken string `kong:"short=t,help='Bearer token value to use for ECS Server',xor='flag'"` // nolint:gosec
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
		return ctx.Store.DeleteEcsBearerToken(ctx.Ctx)
	}

	// Or store the token in the SecureStore
	if ctx.Cli.Setup.Ecs.Auth.BearerToken == "" {
		return fmt.Errorf("no bearer token provided")
	}
	if strings.HasPrefix(ctx.Cli.Setup.Ecs.Auth.BearerToken, "Bearer ") {
		return fmt.Errorf("token should not start with 'Bearer '")
	}
	return ctx.Store.SaveEcsBearerToken(ctx.Ctx, ctx.Cli.Setup.Ecs.Auth.BearerToken)
}

// EcsCaExportFilename is where, under config.ConfigDir(), the local CA certificate
// (never the key) is written so the user can hand it to `security add-trusted-cert`,
// `update-ca-certificates`, `keytool -importcert`, etc. It lives alongside the rest
// of aws-sso's config/store files rather than a separate fixed path: config.ConfigDir()
// treats the mere existence of the legacy ~/.aws-sso directory as a signal to switch
// the whole tool into legacy (non-XDG) mode, so creating a standalone ~/.aws-sso just
// for this file would silently move every other aws-sso config file there too.
const EcsCaExportFilename = "ecs-ca.pem"

type EcsSSLCmd struct {
	Delete     bool `kong:"short=d,help='Disable SSL and delete the local CA',xor='flag'"`
	PrintCa    bool `kong:"help='Print the local self-signed CA certificate and re-print trust instructions',xor='flag'"`
	SelfSigned bool `kong:"help='Generate (or reuse) the local CA for the ECS Server -- a short-lived leaf certificate is minted automatically wherever it is needed',xor='flag'"`
	RotateCa   bool `kong:"help='Force generation of a brand new CA instead of reusing the existing one (requires re-trusting on every client)'"`
}

// AfterApply determines if SSO auth token is required
func (e EcsSSLCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_SKIP
	return nil
}

func (cc *EcsSSLCmd) Run(ctx *RunContext) error {
	switch {
	case ctx.Cli.Setup.Ecs.SSL.Delete:
		return ctx.Store.DeleteEcsCaKeyPair(ctx.Ctx)

	case ctx.Cli.Setup.Ecs.SSL.PrintCa:
		return cc.printCaAndInstructions(ctx, true)
	}

	// --self-signed, or no flag at all: generating (or reusing/rotating) the
	// local CA and issuing a new leaf certificate is the only remaining action.
	return cc.runSelfSigned(ctx)
}

// runSelfSigned reuses the existing local CA (unless --rotate-ca is given, or
// none exists yet) to issue a fresh leaf certificate for the ECS Server.
// Reusing the CA is the entire renewal story: since the CA never changes on a
// normal rerun, nothing needs to be re-trusted in the OS/runtime trust stores.
func (cc *EcsSSLCmd) runSelfSigned(ctx *RunContext) error {
	freshCa, err := cc.loadOrGenerateCa(ctx)
	if err != nil {
		return err
	}

	if freshCa {
		log.Info("Generated a new local CA for the ECS Server.")
	} else {
		log.Info("Reused the existing local CA for the ECS Server.")
		log.Info("The CA has not changed, so no trust-store changes are needed.")
	}

	return cc.printCaAndInstructions(ctx, false)
}

// loadOrGenerateCa confirms a CA is stored, generating and saving a new one
// if --rotate-ca was given or none is stored yet. The bool return indicates
// whether a new CA was generated (true) or an existing one was reused
// (false). The reuse path only needs to confirm a CA cert exists, so it
// never reads the CA private key at all.
func (cc *EcsSSLCmd) loadOrGenerateCa(ctx *RunContext) (bool, error) {
	if !ctx.Cli.Setup.Ecs.SSL.RotateCa {
		caCert, err := ctx.Store.GetEcsCaCert()
		if err != nil {
			return false, err
		}
		if caCert != "" {
			return false, nil
		}
	}

	ca, err := certutil.GenerateCA()
	if err != nil {
		return false, fmt.Errorf("unable to generate CA: %w", err)
	}
	err = ctx.Store.SaveEcsCaKeyPair(ctx.Ctx, []byte(ca.KeyPEM), []byte(ca.CertPEM))
	certutil.ZeroSecret(ca.KeyPEM)
	if err != nil {
		return false, fmt.Errorf("unable to save CA: %w", err)
	}
	return true, nil
}

// printCaAndInstructions exports the current CA certificate under config.ConfigDir()
// and prints per-runtime trust instructions for it. Used by both --self-signed
// (right after generating/reusing a CA) and --print-ca (to re-display the same
// instructions on another machine, or after forgetting them, without touching
// any stored key material). printCert additionally prints the CA certificate
// PEM itself (as --print already does for the leaf certificate) -- only done
// for --print-ca, not after every --self-signed run, so routine rotation
// doesn't dump a full PEM block on every invocation.
func (cc *EcsSSLCmd) printCaAndInstructions(ctx *RunContext, printCert bool) error {
	caCert, err := ctx.Store.GetEcsCaCert()
	if err != nil {
		return err
	}
	if caCert == "" {
		return fmt.Errorf("no local CA found; run 'aws-sso setup ecs ssl --self-signed' first")
	}

	caPath := filepath.Join(config.ConfigDir(true), EcsCaExportFilename)
	if err := fileutils.EnsureDirExists(caPath); err != nil {
		return fmt.Errorf("unable to create directory for %s: %w", caPath, err)
	}
	if err := os.WriteFile(caPath, []byte(caCert), 0644); err != nil { // nolint:gosec
		return fmt.Errorf("unable to write %s: %w", caPath, err)
	}

	fingerprint, err := certutil.Fingerprint(caCert)
	if err != nil {
		return err
	}

	if printCert {
		fmt.Println(caCert)
	}
	fmt.Print(ecsSslTrustInstructions(caPath, fingerprint))
	return nil
}

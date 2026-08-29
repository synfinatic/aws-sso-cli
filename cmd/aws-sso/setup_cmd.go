package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/synfinatic/aws-sso-cli/internal/certutil"
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

// EcsCaExportPath is where the local CA certificate (never the key) is written
// so the user can hand it to `security add-trusted-cert`, `update-ca-certificates`,
// `keytool -importcert`, etc.  Deliberately not under internal/config.ConfigDir():
// that path can be XDG-based and changes across machines/versions, while this one
// is a fixed, predictable location to point OS/runtime trust-store tooling at.
const EcsCaExportPath = "~/.aws-sso/ecs-ca.pem"

type EcsSSLCmd struct {
	Delete      bool     `kong:"short=d,help='Disable SSL and delete the current SSL cert/key and CA',xor='flag,cert,key'"`
	Print       bool     `kong:"short=p,help='Print the current SSL certificate',xor='flag,cert,key'"`
	PrintCa     bool     `kong:"help='Print the local self-signed CA certificate and re-print trust instructions',xor='flag,cert,key'"`
	SelfSigned  bool     `kong:"help='Generate (or reuse) a local CA and issue a new leaf certificate for the ECS Server',xor='flag,cert,key'"`
	San         []string `kong:"help='Additional DNS name or IP address to include in the self-signed leaf certificate (repeatable)',group='self-signed'"`
	RotateCa    bool     `kong:"hidden,help='Force generation of a brand new CA instead of reusing the existing one (requires re-trusting on every client)'"`
	Certificate string   `kong:"short=c,type='existingfile',help='Path to certificate chain PEM file',predictor='allFiles',group='add-ssl',xor='cert'"`
	PrivateKey  string   `kong:"short=k,type='existingfile',help='Path to private key file PEM file',predictor='allFiles',group='add-ssl',xor='key'"` // nolint:gosec
	Force       bool     `kong:"hidden,help='Force loading the certificate'"`
}

// AfterApply determines if SSO auth token is required
func (e EcsSSLCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_SKIP
	return nil
}

func (cc *EcsSSLCmd) Run(ctx *RunContext) error {
	switch {
	case ctx.Cli.Setup.Ecs.SSL.Delete:
		if err := ctx.Store.DeleteEcsCaKeyPair(ctx.Ctx); err != nil {
			return err
		}
		return ctx.Store.DeleteEcsSslKeyPair(ctx.Ctx)

	case ctx.Cli.Setup.Ecs.SSL.Print:
		cert, err := ctx.Store.GetEcsSslCert()
		if err != nil {
			return err
		}
		if cert == "" {
			return fmt.Errorf("no certificate found")
		}
		fmt.Println(cert)
		return nil

	case ctx.Cli.Setup.Ecs.SSL.PrintCa:
		return cc.printCaAndInstructions(ctx)

	case ctx.Cli.Setup.Ecs.SSL.SelfSigned:
		return cc.runSelfSigned(ctx)
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

	return ctx.Store.SaveEcsSslKeyPair(ctx.Ctx, privateKey, certChain)
}

// runSelfSigned reuses the existing local CA (unless --rotate-ca is given, or
// none exists yet) to issue a fresh leaf certificate for the ECS Server.
// Reusing the CA is the entire renewal story: since the CA never changes on a
// normal rerun, nothing needs to be re-trusted in the OS/runtime trust stores.
func (cc *EcsSSLCmd) runSelfSigned(ctx *RunContext) error {
	ca, freshCa, err := cc.loadOrGenerateCa(ctx)
	if err != nil {
		return err
	}

	leaf, err := certutil.GenerateLeaf(ca, ctx.Cli.Setup.Ecs.SSL.San)
	if err != nil {
		return fmt.Errorf("unable to generate leaf certificate: %w", err)
	}

	if err := ctx.Store.SaveEcsSslKeyPair(ctx.Ctx, []byte(leaf.KeyPEM), []byte(leaf.CertPEM)); err != nil {
		return fmt.Errorf("unable to save leaf certificate: %w", err)
	}

	if freshCa {
		log.Info("Generated a new local CA and leaf certificate for the ECS Server.")
	} else {
		log.Info("Reused the existing local CA and issued a new leaf certificate for the ECS Server.")
		log.Info("The CA has not changed, so no trust-store changes are needed.")
	}

	return cc.printCaAndInstructions(ctx)
}

// loadOrGenerateCa returns the existing stored CA unless --rotate-ca was given
// or no CA is stored yet, in which case it generates and saves a new one. The
// bool return indicates whether a new CA was generated (true) or an existing
// one was reused (false).
func (cc *EcsSSLCmd) loadOrGenerateCa(ctx *RunContext) (certutil.KeyPair, bool, error) {
	if !ctx.Cli.Setup.Ecs.SSL.RotateCa {
		caCert, err := ctx.Store.GetEcsCaCert()
		if err != nil {
			return certutil.KeyPair{}, false, err
		}
		caKey, err := ctx.Store.GetEcsCaKey()
		if err != nil {
			return certutil.KeyPair{}, false, err
		}
		if caCert != "" && caKey != "" {
			return certutil.KeyPair{CertPEM: caCert, KeyPEM: caKey}, false, nil
		}
	}

	ca, err := certutil.GenerateCA()
	if err != nil {
		return certutil.KeyPair{}, false, fmt.Errorf("unable to generate CA: %w", err)
	}
	if err := ctx.Store.SaveEcsCaKeyPair(ctx.Ctx, []byte(ca.KeyPEM), []byte(ca.CertPEM)); err != nil {
		return certutil.KeyPair{}, false, fmt.Errorf("unable to save CA: %w", err)
	}
	return ca, true, nil
}

// printCaAndInstructions exports the current CA certificate to EcsCaExportPath
// and prints per-runtime trust instructions for it. Used by both --self-signed
// (right after generating/reusing a CA) and --print-ca (to re-display the same
// instructions on another machine, or after forgetting them, without touching
// any stored key material).
func (cc *EcsSSLCmd) printCaAndInstructions(ctx *RunContext) error {
	caCert, err := ctx.Store.GetEcsCaCert()
	if err != nil {
		return err
	}
	if caCert == "" {
		return fmt.Errorf("no local CA found; run 'aws-sso setup ecs ssl --self-signed' first")
	}

	caPath := fileutils.GetHomePath(EcsCaExportPath)
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

	fmt.Print(ecsSslTrustInstructions(caPath, fingerprint, ctx.Cli.Setup.Ecs.SSL.San))
	return nil
}

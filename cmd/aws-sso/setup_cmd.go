package main

import (
	"fmt"
	"strings"

	"github.com/synfinatic/aws-sso-cli/internal/certutil"
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

// EcsCaTrustDocsURL points to the docs section with the OS/runtime-specific
// steps for trusting the local ECS Server CA certificate. Kept out-of-band in
// the docs (rather than printed inline) so it can't drift out of sync with
// the actual set of supported SDKs/OSes without a docs review.
const EcsCaTrustDocsURL = "https://github.com/synfinatic/aws-sso-cli/blob/main/docs/ecs-server.md#trusting-the-ca"

type EcsSSLCmd struct {
	Delete     bool `kong:"short=d,help='Disable SSL and delete the current SSL cert/key and CA',xor='flag'"`
	PrintCa    bool `kong:"help='Print the local self-signed CA certificate in PEM format',xor='flag'"`
	SelfSigned bool `kong:"help='Generate (or reuse) a local CA and issue a new leaf certificate for the ECS Server',xor='flag'"`
}

// AfterApply determines if SSO auth token is required
func (e EcsSSLCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_SKIP
	return nil
}

func (cc *EcsSSLCmd) Run(ctx *RunContext) error {
	switch {
	case cc.Delete:
		if err := ctx.Store.DeleteEcsSslKeyPair(ctx.Ctx); err != nil {
			return err
		}
		return ctx.Store.DeleteEcsCaKeyPair(ctx.Ctx)

	case cc.PrintCa:
		caCert, err := ctx.Store.GetEcsCaCert()
		if err != nil {
			return err
		}
		if caCert == "" {
			return fmt.Errorf("no local CA found; run 'aws-sso setup ecs ssl --self-signed' first")
		}
		// Print, not Println: the stored PEM already ends in a newline and
		// `--print-ca > ca.pem` should not gain a trailing blank line.
		fmt.Print(caCert)
		return nil

	case cc.SelfSigned:
		return cc.runSelfSigned(ctx)

	default:
		return fmt.Errorf("must specify one of --delete, --print-ca, or --self-signed")
	}
}

// runSelfSigned reuses the existing local CA (generating one if none exists
// yet) to issue a fresh leaf certificate for the ECS Server. Reusing the CA is
// the entire renewal story: since the CA never changes on a normal rerun,
// nothing needs to be re-trusted in the OS/runtime trust stores.
func (cc *EcsSSLCmd) runSelfSigned(ctx *RunContext) error {
	ca, freshCa, err := cc.loadOrGenerateCa(ctx)
	if err != nil {
		return err
	}

	leaf, err := certutil.GenerateLeaf(ca)
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

	// Printed on every run, not just when the CA is new: it is what the user
	// compares against the entry their OS/runtime trust store shows, both when
	// first trusting the CA and when checking later that it is still the same one.
	fingerprint, err := certutil.Fingerprint(ca.CertPEM)
	if err != nil {
		return err
	}
	fmt.Printf("\nCA SHA-256 fingerprint:\n  %s\n", fingerprint)

	fmt.Printf("\nFor instructions on exporting and trusting this CA, see:\n  %s\n", EcsCaTrustDocsURL)
	return nil
}

// loadOrGenerateCa returns the existing stored CA, or generates and saves a
// new one if none is stored yet. The bool return indicates whether a new CA
// was generated (true) or an existing one was reused (false).
func (cc *EcsSSLCmd) loadOrGenerateCa(ctx *RunContext) (certutil.KeyPair, bool, error) {
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

	ca, err := certutil.GenerateCA()
	if err != nil {
		return certutil.KeyPair{}, false, fmt.Errorf("unable to generate CA: %w", err)
	}
	if err := ctx.Store.SaveEcsCaKeyPair(ctx.Ctx, []byte(ca.KeyPEM), []byte(ca.CertPEM)); err != nil {
		return certutil.KeyPair{}, false, fmt.Errorf("unable to save CA: %w", err)
	}
	return ca, true, nil
}

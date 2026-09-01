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
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/synfinatic/aws-sso-cli/internal/certutil"
	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	"github.com/synfinatic/aws-sso-cli/internal/ecs/server"
)

// ecsCaCertExpiryWarningWindow is how far ahead of the CA certificate's
// expiration `ecs server` starts warning on startup, giving the user time to
// rerun `aws-sso setup ecs ssl --rotate-ca` -- and to redo the trust-store
// steps on every client -- before TLS handshakes start failing.
const ecsCaCertExpiryWarningWindow = 30 * 24 * time.Hour

// ecsLeafCertExpiryWarningWindow is necessarily much shorter than the CA's: the
// leaf is only valid for certutil.LeafValidity (30 days) to begin with, so a
// 30-day window would warn over a leaf's entire lifetime.  Host-side ECS
// commands refresh a persisted leaf well before this fires, so reaching it
// means none have run in weeks.
const ecsLeafCertExpiryWarningWindow = 7 * 24 * time.Hour

type EcsServerCmd struct {
	BindIP  string `kong:"help='Bind address for ECS Server',default='127.0.0.1'"`
	Port    int    `kong:"help='TCP port to listen on',default=4144"`
	Default string `kong:"short='d',help='Profile name to load as default credentials on start',predictor='profile'"`
	// hidden flags are for internal use only when running in a docker container
	Docker      bool `kong:"hidden"`
	DisableAuth bool `kong:"help='Disable HTTP Auth for the ECS Server (ignored with --docker; use \"ecs docker secrets --disable-auth\")'"`
	DisableSSL  bool `kong:"help='Disable SSL/TLS for the ECS Server (ignored with --docker; use \"ecs docker secrets --disable-ssl\")'"`
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
	var disableSSL, disableAuth bool
	if ctx.Cli.Ecs.Server.Docker {
		if ctx.Cli.Ecs.Server.DisableSSL || ctx.Cli.Ecs.Server.DisableAuth {
			log.Warn("--disable-ssl/--disable-auth have no effect under --docker: the " +
				"security config written by `aws-sso ecs docker secrets` is the source " +
				"of truth for TLS and HTTP Auth in this mode")
		}

		// Read the security config bind-mounted in from the host.  The file is
		// deliberately left in place: docker compose owns the container
		// lifecycle, so this process can be restarted or recreated at any time
		// and has to come back up with the same security posture.
		f, err := ecs.OpenContainerSecurityFile()
		if err != nil {
			// Fail closed, unconditionally: Docker mode no longer takes this
			// decision from its own CLI flags at all, since the security file
			// -- always written by `ecs docker secrets`/`ecs docker start`,
			// even when nothing is configured -- is the sole source of truth.
			// Name the container-side path, since that is what actually
			// failed, but point at the host: the directory mounted onto
			// CONTAINER_MOUNT_POINT is the thing that needs fixing, and this
			// process cannot know its path on the host.
			return fmt.Errorf("unable to read the ECS security config %s: %w\n"+
				"Run `aws-sso ecs docker secrets` on the host and bind-mount the "+
				"directory it names onto %s -- if you set --secrets-dir or "+
				"AWS_SSO_ECS_SECRETS_DIR, that is the directory to mount.  Pass "+
				"--disable-auth/--disable-ssl to that command to intentionally start "+
				"without HTTP Auth and/or SSL/TLS",
				ecs.ContainerSecurityFilePath(), err, ecs.CONTAINER_MOUNT_POINT)
		}
		creds, err := ecs.ReadSecurityConfig(f)
		// have to manually close since defer won't work in this case
		f.Close()
		if err != nil {
			return err
		}

		bearerToken = creds.BearerToken
		privateKey = creds.PrivateKey
		certChain = creds.CertChain
		disableSSL = creds.DisableSSL
		disableAuth = creds.DisableAuth

		if (privateKey == "" || certChain == "") && !disableSSL {
			return fmt.Errorf("the ECS security config %s has no SSL/TLS material, and it "+
				"was not written with --disable-ssl -- refusing to start without TLS.  Run "+
				"`aws-sso setup ecs ssl --self-signed` then `aws-sso ecs docker secrets`, or "+
				"`aws-sso ecs docker secrets --disable-ssl` to start without TLS intentionally",
				ecs.ContainerSecurityFilePath())
		}
		if bearerToken == "" && !disableAuth {
			return fmt.Errorf("the ECS security config %s has no HTTP Auth bearer token, and "+
				"it was not written with --disable-auth -- refusing to start without HTTP "+
				"Auth.  Run `aws-sso setup ecs auth` then `aws-sso ecs docker secrets`, or "+
				"`aws-sso ecs docker secrets --disable-auth` to start without HTTP Auth "+
				"intentionally", ecs.ContainerSecurityFilePath())
		}
	} else {
		if bearerToken, err = ctx.Store.GetEcsBearerToken(); err != nil {
			return err
		}

		caCert, err := ctx.Store.GetEcsCaCert()
		if err != nil {
			return err
		}
		caKey, err := ctx.Store.GetEcsCaKey()
		if err != nil {
			return err
		}
		if caCert != "" && caKey != "" {
			// Clone before use: SecureStorage backends return their cached key
			// string directly, sharing its backing array. ZeroSecret-ing that
			// shared array in place would corrupt the store's own in-memory
			// copy instead of just scrubbing our local, single-use copy.
			caKey = strings.Clone(caKey)
			leaf, leafErr := certutil.GenerateLeaf(certutil.KeyPair{CertPEM: caCert, KeyPEM: caKey})
			certutil.ZeroSecret(caKey)
			if leafErr != nil {
				return fmt.Errorf("unable to generate leaf certificate: %w", leafErr)
			}
			privateKey, certChain = leaf.KeyPEM, leaf.CertPEM
		}

		disableSSL = ctx.Cli.Ecs.Server.DisableSSL
		disableAuth = ctx.Cli.Ecs.Server.DisableAuth

		// Disable SSL, even if configured
		if disableSSL {
			privateKey = ""
			certChain = ""
		}
		if disableAuth {
			bearerToken = ""
		}
	}

	if bearerToken == "" && !disableAuth {
		log.Warn("HTTP Auth: disabled. Use 'aws-sso setup ecs auth' to enable")
	} else {
		log.Info("HTTP Auth: enabled")
	}

	if privateKey != "" && certChain != "" {
		log.Info("SSL/TLS: enabled")

		if ctx.Cli.Ecs.Server.Docker {
			// No CA is available inside the container, but the leaf's own expiry
			// is right here -- and under docker the leaf is persisted in the
			// security file rather than minted fresh per start, so it is the one
			// that can actually go stale.
			warnIfCertExpiringSoon(certChain, "leaf certificate",
				"aws-sso ecs docker secrets", ecsLeafCertExpiryWarningWindow)
		} else if caCert, err := ctx.Store.GetEcsCaCert(); err == nil && caCert != "" {
			warnIfCertExpiringSoon(caCert, "CA certificate",
				"aws-sso setup ecs ssl --rotate-ca", ecsCaCertExpiryWarningWindow)
		}
	} else if !disableSSL {
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

	// Shut down gracefully when the context is cancelled (handles SIGINT/SIGTERM from main).
	go func() {
		<-ctx.Ctx.Done()
		s.Close()
	}()

	if err := s.Serve(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// warnIfCertExpiringSoon logs a warning if certPEM expires within window (or
// has already expired), naming the fixCmd the user should rerun. Parse errors
// are ignored here: certificates loaded from the SecureStore have already been
// validated when they were saved.
func warnIfCertExpiringSoon(certPEM, label, fixCmd string, window time.Duration) {
	notAfter, err := certutil.NotAfter(certPEM)
	if err != nil {
		return
	}

	if msg := certExpiryWarning(label, notAfter, time.Now(), window); msg != "" {
		log.Warn(msg, "expires", notAfter.Format(time.RFC3339), "fix", fixCmd)
	}
}

// certExpiryWarning returns a warning message if notAfter is at or before
// now, or within window of now; otherwise it returns "".
func certExpiryWarning(label string, notAfter, now time.Time, window time.Duration) string {
	remaining := notAfter.Sub(now)
	switch {
	case remaining <= 0:
		return fmt.Sprintf("SSL/TLS %s has expired", label)
	case remaining < window:
		return fmt.Sprintf("SSL/TLS %s expires soon", label)
	default:
		return ""
	}
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

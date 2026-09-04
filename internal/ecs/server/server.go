package server

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
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	// "github.com/davecgh/go-spew/spew"
	"time"

	"github.com/synfinatic/aws-sso-cli/internal/certutil"
	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	"github.com/synfinatic/aws-sso-cli/internal/logger"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	"github.com/synfinatic/flexlog"
)

var log flexlog.FlexLogger

func init() {
	log = logger.GetLogger()
}

type EcsServer struct {
	listener     net.Listener
	authToken    string
	server       http.Server
	DefaultCreds *ecs.ECSClientRequest
	slottedCreds map[string]*ecs.ECSClientRequest
	privateKey   string
	certChain    string
}

type ExpiredCredentials struct{}

func (e *ExpiredCredentials) Error() string {
	return "Expired Credentials"
}

// NewEcsServer creates a new ECS Server
func NewEcsServer(ctx context.Context, authToken string, listen net.Listener, privateKey, certChain string) (*EcsServer, error) {
	e := &EcsServer{
		listener:  listen,
		authToken: authToken,
		DefaultCreds: &ecs.ECSClientRequest{
			Creds: &storage.RoleCredentials{},
		},
		slottedCreds: map[string]*ecs.ECSClientRequest{},
		privateKey:   privateKey,
		certChain:    certChain,
	}

	// inner router: all auth-protected credential routes
	innerRouter := http.NewServeMux()
	innerRouter.Handle(ecs.SLOT_ROUTE, SlottedHandler{
		ecs: e,
	})
	innerRouter.Handle(fmt.Sprintf("%s/", ecs.SLOT_ROUTE), SlottedHandler{
		ecs: e,
	})
	innerRouter.Handle(ecs.PROFILE_ROUTE, ProfileHandler{
		ecs: e,
	})
	innerRouter.Handle(ecs.DEFAULT_ROUTE, DefaultHandler{
		ecs: e,
	})
	authTokenHeader := ""
	if e.authToken != "" {
		authTokenHeader = "Bearer " + e.authToken
	}

	healthHandler := HealthCheckHandler{ecs: e}

	// outer router: healthcheck bypasses auth; all other routes require auth
	outerRouter := http.NewServeMux()
	outerRouter.Handle(ecs.HEALTHCHECK_ROUTE, healthHandler)
	outerRouter.Handle(fmt.Sprintf("%s/", ecs.HEALTHCHECK_ROUTE), healthHandler)
	outerRouter.Handle(ecs.DEFAULT_ROUTE, WithAuthorizationCheck(authTokenHeader, innerRouter.ServeHTTP))
	e.server.Handler = withLogging(outerRouter)

	return e, nil
}

// deleteCreds removes our slotted credentials from the cache
func (e *EcsServer) DeleteSlottedCreds(profile string) error {
	if _, ok := e.slottedCreds[profile]; ok {
		delete(e.slottedCreds, profile)
		return nil
	}
	return fmt.Errorf("%s is not found", profile)
}

// getCreds fetches the named profile from the cache.
func (e *EcsServer) GetSlottedCreds(profile string) (*ecs.ECSClientRequest, error) {
	log.Debug("fetching creds", "profile", profile)
	c, ok := e.slottedCreds[profile]
	if !ok {
		return c, fmt.Errorf("%s is not found", profile)
	}
	return c, nil
}

// putCreds loads credentials into the cache
func (e *EcsServer) PutSlottedCreds(creds *ecs.ECSClientRequest) error {
	if creds.Creds.Expired() {
		return fmt.Errorf("expired creds")
	}

	e.warnIfCertExpiringSoon()
	e.slottedCreds[creds.ProfileName] = creds
	return nil
}

// warnIfCertExpiringSoon logs a warning if the server's TLS cert (if any)
// expires within certutil.CertExpiryWarning.
func (e *EcsServer) warnIfCertExpiringSoon() {
	if e.certChain == "" {
		return
	}

	soon, notAfter, err := certutil.ExpiringSoon(e.certChain)
	if err != nil {
		log.Error("unable to check ECS server TLS cert expiry", "error", err.Error())
		return
	}

	if soon {
		log.Warn("ECS server TLS cert is expiring soon",
			"expires", notAfter.Format(time.RFC3339),
			"hint", "run `aws-sso setup ecs ssl --self-signed` to rotate it")
	}
}

// ListSlottedCreds returns the list of roles in our slots
func (e *EcsServer) ListSlottedCreds() []ecs.ListProfilesResponse {
	resp := []ecs.ListProfilesResponse{}

	for _, cr := range e.slottedCreds {
		if cr.Creds.Expired() {
			log.Error("Skipping expired creds", "profile", cr.ProfileName)
			continue
		}

		resp = append(resp, ecs.NewListProfileRepsonse(cr))
	}

	return resp
}

// BaseURL returns our the base URL for all requests
func (e *EcsServer) BaseURL() string {
	proto := "http"
	if e.privateKey != "" && e.certChain != "" {
		proto = "https"
	}
	return fmt.Sprintf("%s://%s", proto, e.listener.Addr().String())
}

// Serve starts the sever and blocks
func (e *EcsServer) Serve() error {
	if e.privateKey != "" && e.certChain != "" {
		// Keep the key in memory: ServeTLS only reads certFile/keyFile off disk
		// when TLSConfig has no certificate of its own, so load the PEM directly
		// and pass empty paths.
		cert, err := tls.X509KeyPair([]byte(e.certChain), []byte(e.privateKey))
		if err != nil {
			return fmt.Errorf("invalid ECS server certificate: %w", err)
		}

		if e.server.TLSConfig == nil {
			e.server.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
		}
		e.server.TLSConfig.Certificates = []tls.Certificate{cert}

		return e.server.ServeTLS(e.listener, "", "")
	}
	return e.server.Serve(e.listener)
}

// WithAuthorizationCheck checks our authToken (if set) and returns 404 on error
func WithAuthorizationCheck(authToken string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != authToken {
			ecs.WriteMessage(w, "Invalid authorization token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func (e *EcsServer) Close() {
	e.server.Close()
}

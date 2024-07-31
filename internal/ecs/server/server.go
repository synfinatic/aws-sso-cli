package server

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
	"net/http"
	"os"
	"path/filepath"

	// "github.com/davecgh/go-spew/spew"
	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	"github.com/synfinatic/aws-sso-cli/internal/logger"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

var log *logger.Logger

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

	router := http.NewServeMux()
	router.Handle(ecs.SLOT_ROUTE, SlottedHandler{
		ecs: e,
	})
	router.Handle(fmt.Sprintf("%s/", ecs.SLOT_ROUTE), SlottedHandler{
		ecs: e,
	})
	router.Handle(ecs.PROFILE_ROUTE, ProfileHandler{
		ecs: e,
	})
	router.Handle(ecs.DEFAULT_ROUTE, DefaultHandler{
		ecs: e,
	})
	authTokenHeader := ""
	if e.authToken != "" {
		authTokenHeader = "Bearer " + e.authToken
	}
	e.server.Handler = withLogging(WithAuthorizationCheck(authTokenHeader, router.ServeHTTP))

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

	e.slottedCreds[creds.ProfileName] = creds
	return nil
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
		// Go sucks... have to pass the key and cert as _files_ not strings.  Why???
		dname, err := os.MkdirTemp("", "aws-sso")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dname)

		certFile := filepath.Join(dname, "cert.pem")
		err = os.WriteFile(certFile, []byte(e.certChain), 0600)
		if err != nil {
			return err
		}
		keyFile := filepath.Join(dname, "key.pem")
		err = os.WriteFile(keyFile, []byte(e.privateKey), 0600)
		if err != nil {
			return err
		}

		return e.server.ServeTLS(e.listener, certFile, keyFile)
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

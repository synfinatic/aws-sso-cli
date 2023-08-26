package server

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2023 Aaron Turner  <synfinatic at gmail dot com>
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

	// "github.com/davecgh/go-spew/spew"
	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

type EcsServer struct {
	listener     net.Listener
	authToken    string
	server       http.Server
	DefaultCreds *ecs.ECSClientRequest
	slottedCreds map[string]*ecs.ECSClientRequest
}

type ExpiredCredentials struct{}

func (e *ExpiredCredentials) Error() string {
	return "Expired Credentials"
}

// NewEcsServer creates a new ECS Server
func NewEcsServer(ctx context.Context, authToken string, listen net.Listener) (*EcsServer, error) {
	e := &EcsServer{
		listener:  listen,
		authToken: authToken,
		DefaultCreds: &ecs.ECSClientRequest{
			Creds: &storage.RoleCredentials{},
		},
		slottedCreds: map[string]*ecs.ECSClientRequest{},
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
	e.server.Handler = withLogging(WithAuthorizationCheck(e.authToken, router.ServeHTTP))

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
	log.Debugf("fetching creds for profile: %s", profile)
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
			log.Errorf("Skipping expired creds for %s", cr.ProfileName)
			continue
		}

		resp = append(resp, ecs.NewListProfileRepsonse(cr))
	}

	return resp
}

// BaseURL returns our the base URL for all requests
func (e *EcsServer) BaseURL() string {
	return fmt.Sprintf("http://%s", e.listener.Addr().String())
}

// AuthToken returns our authToken for authentication
func (e *EcsServer) AuthToken() string {
	return e.authToken
}

// Serve starts the sever and blocks
func (e *EcsServer) Serve() error {
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

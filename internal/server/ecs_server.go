package server

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2022 Aaron Turner  <synfinatic at gmail dot com>
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
 *
 * This file is heavily based on that by 99designs:
 * https://github.com/99designs/aws-vault/blob/master/server/ecsserver.go
 *
 * Copyright (c) 2015 99designs
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/synfinatic/aws-sso-cli/internal/storage"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

type EcsServer struct {
	listener     net.Listener
	authToken    string
	server       http.Server
	defaultCreds *ClientRequest
	credentials  map[string]*ClientRequest
}

const (
	CREDS_ROUTE   = "/creds"   // put/get/delete
	PROFILE_ROUTE = "/profile" // get
	DEFAULT_ROUTE = "/"        // get: default route
	CHARSET_JSON  = "application/json; charset=utf-8"
)

// NewEcsServer creates a new ECS Server
func NewEcsServer(ctx context.Context, authToken string, port int) (*EcsServer, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}

	e := &EcsServer{
		listener:  listener,
		authToken: authToken,
		defaultCreds: &ClientRequest{
			Creds: &storage.RoleCredentials{},
		},
		credentials: map[string]*ClientRequest{},
	}

	router := http.NewServeMux()
	router.HandleFunc(DEFAULT_ROUTE, e.DefaultRoute)
	router.HandleFunc(CREDS_ROUTE, e.CredsRoute)
	router.HandleFunc(PROFILE_ROUTE, e.ProfileRoute)
	e.server.Handler = withLogging(withAuthorizationCheck(e.authToken, router.ServeHTTP))

	return e, nil
}

// Serve starts the sever and blocks
func (e *EcsServer) Serve() error {
	return e.server.Serve(e.listener)
}

func (e *EcsServer) DefaultRoute(w http.ResponseWriter, r *http.Request) {
	log.Errorf("Invalid request")
	e.Invalid(w)
}

// CredsRoutef accepts GET, PUT, DELETE to manage our creds.  The path
// compoent after the first word indicates a named slot.  Lack of a named
// slot utilizes the defaultCreds
func (e *EcsServer) CredsRoute(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	profile := query.Get("profile")

	switch r.Method {
	case http.MethodGet:
		if len(profile) > 0 {
			log.Errorf("trying to getCreds")
			e.getCreds(w, r, profile)
		} else {
			log.Errorf("trying to listCreds")
			e.listCreds(w, r)
		}
	case http.MethodPut:
		e.putCreds(w, r, profile)
	case http.MethodDelete:
		e.deleteCreds(w, r, profile)
	default:
		log.Errorf("What?")
		e.Invalid(w)
	}
}

// deleteCreds removes our credentials from the cache
func (e *EcsServer) deleteCreds(w http.ResponseWriter, r *http.Request, profile string) {
	if profile == "" {
		e.defaultCreds = &ClientRequest{
			ProfileName: "",
		}
	} else {
		delete(e.credentials, profile)
	}
	e.OK(w)
}

// getCreds fetches the credentials from the cache
func (e *EcsServer) getCreds(w http.ResponseWriter, r *http.Request, profile string) {
	var c *ClientRequest
	var ok bool
	if profile == "" {
		log.Debugf("fetching default creds")
		c = e.defaultCreds
	} else {
		log.Debugf("fetching creds for profile: %s", profile)
		c, ok = e.credentials[profile]
		if !ok {
			e.Unavailable(w)
			return
		}
	}

	if c.Creds.Expired() {
		e.Expired(w)
		return
	}
	writeCredsToResponse(c.Creds, w)
}

func (e *EcsServer) getClientRequest(r *http.Request) (*ClientRequest, error) {
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return &ClientRequest{}, fmt.Errorf("reading body: %s", err.Error())
	}
	creds := &ClientRequest{}
	if err = json.Unmarshal(body, creds); err != nil {
		return &ClientRequest{}, fmt.Errorf("parsing json: %s", err.Error())
	}
	return creds, nil
}

// putCreds loads credentials into the cache
func (e *EcsServer) putCreds(w http.ResponseWriter, r *http.Request, profile string) {
	creds, err := e.getClientRequest(r)
	if err != nil {
		writeMessage(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if creds.Creds.Expired() {
		e.Expired(w)
		return
	}
	if profile == "" {
		e.defaultCreds = creds
	} else {
		e.credentials[creds.ProfileName] = creds
	}
	e.OK(w)
}

// listCreds returns the list of roles in our slots
func (e *EcsServer) listCreds(w http.ResponseWriter, r *http.Request) {
	resp := []ListProfilesResponse{}

	for _, cr := range e.credentials {
		exp, _ := utils.TimeRemain(cr.Creds.Expiration/1000, true)
		resp = append(resp, ListProfilesResponse{
			ProfileName:  cr.ProfileName,
			AccountIdPad: cr.Creds.AccountIdStr(),
			RoleName:     cr.Creds.RoleName,
			Expiration:   cr.Creds.Expiration / 1000,
			Expires:      exp,
		})
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Error(err.Error())
	}
}

// RoleRoute returns the current ProfileName in the defaultCreds
func (e *EcsServer) ProfileRoute(w http.ResponseWriter, r *http.Request) {
	if e.defaultCreds.ProfileName == "" {
		e.Unavailable(w)
		return
	}

	if e.defaultCreds.Creds.Expired() {
		e.Expired(w)
		return
	}

	w.Header().Set("Content-Type", CHARSET_JSON)
	w.WriteHeader(http.StatusOK)
	profile := e.defaultCreds.ProfileName
	if err := json.NewEncoder(w).Encode(map[string]string{"profile": profile}); err != nil {
		log.Error(err.Error())
	}
}

func (e *EcsServer) BaseURL() string {
	return fmt.Sprintf("http://%s", e.listener.Addr().String())
}

func (e *EcsServer) AuthToken() string {
	return e.authToken
}

// OK returns an OK response
func (e *EcsServer) OK(w http.ResponseWriter) {
	writeMessage(w, "OK", http.StatusOK)
}

// Expired returns a credentials expired response
func (e *EcsServer) Expired(w http.ResponseWriter) {
	writeMessage(w, "Credentials expired", http.StatusConflict)
}

// Unavailable returns a credentials unavailable response
func (e *EcsServer) Unavailable(w http.ResponseWriter) {
	writeMessage(w, "Credentials unavailable", http.StatusNotFound)
}

// Invalid returns an invalid request response
func (e *EcsServer) Invalid(w http.ResponseWriter) {
	writeMessage(w, "Invalid request", http.StatusNotFound)
}

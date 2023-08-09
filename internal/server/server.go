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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

func writeErrorMessage(w http.ResponseWriter, msg string, statusCode int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(map[string]string{"Message": msg}); err != nil {
		log.Println(err.Error())
	}
}

func withAuthorizationCheck(authToken string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != authToken {
			writeErrorMessage(w, "invalid Authorization token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func writeCredsToResponse(creds *storage.RoleCredentials, w http.ResponseWriter) {
	err := json.NewEncoder(w).Encode(map[string]string{
		"AccessKeyId":     creds.AccessKeyId,
		"SecretAccessKey": creds.SecretAccessKey,
		"Token":           creds.SessionToken,
		"Expiration":      creds.ExpireISO8601(),
	})
	if err != nil {
		writeErrorMessage(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func generateRandomString() string {
	b := make([]byte, 30)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

type EcsServer struct {
	listener    net.Listener
	authToken   string
	server      http.Server
	credentials *storage.RoleCredentials
}

func NewEcsServer(ctx context.Context, authToken string, port int) (*EcsServer, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	if authToken == "" {
		authToken = generateRandomString()
	}

	e := &EcsServer{
		listener:  listener,
		authToken: authToken,
	}

	router := http.NewServeMux()
	router.HandleFunc("/", e.DefaultRoute)
	router.HandleFunc("/load-creds/", e.LoadCredsRoute)
	e.server.Handler = withLogging(withAuthorizationCheck(e.authToken, router.ServeHTTP))

	return e, nil
}

func (e *EcsServer) BaseURL() string {
	return fmt.Sprintf("http://%s", e.listener.Addr().String())
}
func (e *EcsServer) AuthToken() string {
	return e.authToken
}

func (e *EcsServer) Serve() error {
	return e.server.Serve(e.listener)
}

func (e *EcsServer) DefaultRoute(w http.ResponseWriter, r *http.Request) {
	if e.credentials.Expired() {
		writeErrorMessage(w, "Credentials expired.", http.StatusInternalServerError)
		return
	}
	writeCredsToResponse(e.credentials, w)
}

// PUT
func (e *EcsServer) LoadCredsRoute(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		writeErrorMessage(w, err.Error(), http.StatusInternalServerError)
		return
	}
	credsStr := r.PostFormValue("creds")
	creds := &storage.RoleCredentials{}
	if err = json.Unmarshal([]byte(credsStr), creds); err != nil {
		writeErrorMessage(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if creds.Expired() {
		writeErrorMessage(w, "Credentials expired.", http.StatusInternalServerError)
		return
	}
	e.credentials = creds
}

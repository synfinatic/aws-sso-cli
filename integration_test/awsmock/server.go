//go:build integration

package awsmock

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
	"encoding/json"
	"net/http"
	"net/http/httptest"
)

// MockAWSServer simulates the AWS SSO OIDC, SSO, and STS HTTP APIs for integration tests.
// All three services share a single httptest.Server, routed by URL path.
type MockAWSServer struct {
	server  *httptest.Server
	SSOOIDC *SSOOIDCHandler
	SSO     *SSOHandler
	STS     *STSHandler
}

// NewMockAWSServer creates and starts a mock AWS server.
// Call Close() when done.
func NewMockAWSServer() *MockAWSServer {
	s := &MockAWSServer{
		SSOOIDC: &SSOOIDCHandler{},
		SSO:     &SSOHandler{},
		STS:     &STSHandler{},
	}

	mux := http.NewServeMux()

	// SSO OIDC endpoints
	mux.HandleFunc("/client/register", s.SSOOIDC.handleRegisterClient)
	mux.HandleFunc("/device_authorization", s.SSOOIDC.handleDeviceAuthorization)
	mux.HandleFunc("/token", s.SSOOIDC.handleToken)

	// SSO API endpoints
	mux.HandleFunc("/assignment/accounts", s.SSO.handleListAccounts)
	mux.HandleFunc("/assignment/roles", s.SSO.handleListAccountRoles)
	mux.HandleFunc("/federation/credentials", s.SSO.handleGetRoleCredentials)
	mux.HandleFunc("/logout", s.SSO.handleLogout)

	// STS (Action=AssumeRole posted to /)
	mux.HandleFunc("/", s.STS.handleSTS)

	s.server = httptest.NewServer(mux)
	return s
}

// URL returns the base URL of the mock server (e.g., "http://127.0.0.1:PORT").
func (s *MockAWSServer) URL() string {
	return s.server.URL
}

// Close shuts down the mock server.
func (s *MockAWSServer) Close() {
	s.server.Close()
}

// queueItem holds one response to serve from a handler queue.
// body is JSON-marshallable for successful responses; use a string for error bodies.
// A nil body with status 200 writes a 200 with no response body.
type queueItem struct {
	status int
	body   interface{}
}

func dequeue(q *[]queueItem) (queueItem, bool) {
	if len(*q) == 0 {
		return queueItem{}, false
	}
	item := (*q)[0]
	*q = (*q)[1:]
	return item, true
}

func writeQueueItem(w http.ResponseWriter, item queueItem, found bool) {
	if !found {
		http.Error(w, "no queued responses", http.StatusInternalServerError)
		return
	}
	if item.status != http.StatusOK {
		if msg, isStr := item.body.(string); isStr {
			http.Error(w, msg, item.status)
		} else {
			w.WriteHeader(item.status)
		}
		return
	}
	if item.body == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(item.body)
}

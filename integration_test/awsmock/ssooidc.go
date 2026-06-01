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
	"net/http"
	"sync"
)

// RegisterClientResponse is the mock response body for POST /client/register.
// Field names match the AWS SSO OIDC REST-JSON protocol.
type RegisterClientResponse struct {
	ClientID              string `json:"clientId"`
	ClientSecret          string `json:"clientSecret"`
	ClientIDIssuedAt      int64  `json:"clientIdIssuedAt"`
	ClientSecretExpiresAt int64  `json:"clientSecretExpiresAt"`
	AuthorizationEndpoint string `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint         string `json:"tokenEndpoint,omitempty"`
}

// DeviceAuthResponse is the mock response body for POST /device_authorization.
type DeviceAuthResponse struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	ExpiresIn               int32  `json:"expiresIn"`
	Interval                int32  `json:"interval"`
}

// OIDCTokenResponse is the mock response body for POST /token.
type OIDCTokenResponse struct {
	AccessToken  string `json:"accessToken"`
	ExpiresIn    int32  `json:"expiresIn"`
	IDToken      string `json:"idToken,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty"`
	TokenType    string `json:"tokenType"`
}

// SSOOIDCHandler handles SSO OIDC API endpoints.
type SSOOIDCHandler struct {
	mu          sync.Mutex
	registerQ   []queueItem
	deviceAuthQ []queueItem
	tokenQ      []queueItem
}

// QueueRegisterClient enqueues a successful RegisterClient response.
func (h *SSOOIDCHandler) QueueRegisterClient(r RegisterClientResponse) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.registerQ = append(h.registerQ, queueItem{status: http.StatusOK, body: r})
}

// QueueRegisterClientError enqueues an error response for RegisterClient.
func (h *SSOOIDCHandler) QueueRegisterClientError(status int, msg string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.registerQ = append(h.registerQ, queueItem{status: status, body: msg})
}

// QueueDeviceAuth enqueues a successful StartDeviceAuthorization response.
func (h *SSOOIDCHandler) QueueDeviceAuth(r DeviceAuthResponse) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.deviceAuthQ = append(h.deviceAuthQ, queueItem{status: http.StatusOK, body: r})
}

// QueueCreateToken enqueues a successful CreateToken response.
func (h *SSOOIDCHandler) QueueCreateToken(r OIDCTokenResponse) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tokenQ = append(h.tokenQ, queueItem{status: http.StatusOK, body: r})
}

func (h *SSOOIDCHandler) handleRegisterClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.mu.Lock()
	item, found := dequeue(&h.registerQ)
	h.mu.Unlock()
	writeQueueItem(w, item, found)
}

func (h *SSOOIDCHandler) handleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.mu.Lock()
	item, found := dequeue(&h.deviceAuthQ)
	h.mu.Unlock()
	writeQueueItem(w, item, found)
}

func (h *SSOOIDCHandler) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.mu.Lock()
	item, found := dequeue(&h.tokenQ)
	h.mu.Unlock()
	writeQueueItem(w, item, found)
}

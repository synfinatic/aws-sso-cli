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

// AccountInfo is an entry in a ListAccounts response.
// Field names match the AWS SSO Portal REST-JSON protocol.
type AccountInfo struct {
	AccountID    string `json:"accountId"`
	AccountName  string `json:"accountName"`
	EmailAddress string `json:"emailAddress"`
}

// ListAccountsResponse is the mock response for GET /assignment/accounts.
type ListAccountsResponse struct {
	AccountList []AccountInfo `json:"accountList"`
	NextToken   string        `json:"nextToken,omitempty"`
}

// RoleInfo is an entry in a ListAccountRoles response.
type RoleInfo struct {
	AccountID string `json:"accountId"`
	RoleName  string `json:"roleName"`
}

// ListAccountRolesResponse is the mock response for GET /assignment/roles.
type ListAccountRolesResponse struct {
	RoleList  []RoleInfo `json:"roleList"`
	NextToken string     `json:"nextToken,omitempty"`
}

// RoleCredentials is the credentials block inside a GetRoleCredentials response.
type RoleCredentials struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
	SessionToken    string `json:"sessionToken"`
	Expiration      int64  `json:"expiration"` // milliseconds since epoch
}

// GetRoleCredentialsResponse is the mock response for GET /federation/credentials.
type GetRoleCredentialsResponse struct {
	RoleCredentials RoleCredentials `json:"roleCredentials"`
}

// SSOHandler handles SSO API endpoints.
type SSOHandler struct {
	mu                sync.Mutex
	listAccountsQ     []queueItem
	listAccountRolesQ []queueItem
	getRoleCredsQ     []queueItem
	logoutQ           []queueItem
}

// QueueListAccounts enqueues a ListAccounts response.
func (h *SSOHandler) QueueListAccounts(r ListAccountsResponse) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.listAccountsQ = append(h.listAccountsQ, queueItem{status: http.StatusOK, body: r})
}

// QueueListAccountRoles enqueues a ListAccountRoles response.
func (h *SSOHandler) QueueListAccountRoles(r ListAccountRolesResponse) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.listAccountRolesQ = append(h.listAccountRolesQ, queueItem{status: http.StatusOK, body: r})
}

// QueueGetRoleCredentials enqueues a GetRoleCredentials response.
func (h *SSOHandler) QueueGetRoleCredentials(r GetRoleCredentialsResponse) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.getRoleCredsQ = append(h.getRoleCredsQ, queueItem{status: http.StatusOK, body: r})
}

// QueueLogout enqueues a successful Logout response.
func (h *SSOHandler) QueueLogout() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.logoutQ = append(h.logoutQ, queueItem{status: http.StatusOK, body: nil})
}

func (h *SSOHandler) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	item, found := dequeue(&h.listAccountsQ)
	h.mu.Unlock()
	writeQueueItem(w, item, found)
}

func (h *SSOHandler) handleListAccountRoles(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	item, found := dequeue(&h.listAccountRolesQ)
	h.mu.Unlock()
	writeQueueItem(w, item, found)
}

func (h *SSOHandler) handleGetRoleCredentials(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	item, found := dequeue(&h.getRoleCredsQ)
	h.mu.Unlock()
	writeQueueItem(w, item, found)
}

func (h *SSOHandler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.mu.Lock()
	item, found := dequeue(&h.logoutQ)
	h.mu.Unlock()
	writeQueueItem(w, item, found)
}

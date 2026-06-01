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
	"encoding/xml"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// AssumeRoleResult is queued via STSHandler.QueueAssumeRole.
type AssumeRoleResult struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
	// RoleARN is used to populate AssumedRoleUser.Arn in the response.
	RoleARN string
	// SessionName populates AssumedRoleUser.AssumedRoleId suffix.
	SessionName string
}

// stsAssumeRoleResponse is the XML body for a successful AssumeRole response.
type stsAssumeRoleResponse struct {
	XMLName          xml.Name            `xml:"https://sts.amazonaws.com/doc/2011-06-15/ AssumeRoleResponse"`
	AssumeRoleResult stsAssumeRoleResult `xml:"AssumeRoleResult"`
	ResponseMetadata stsResponseMetadata `xml:"ResponseMetadata"`
}

type stsAssumeRoleResult struct {
	Credentials     stsCredentials    `xml:"Credentials"`
	AssumedRoleUser stsAssumedRoleUser `xml:"AssumedRoleUser"`
}

type stsCredentials struct {
	AccessKeyID     string `xml:"AccessKeyId"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
	Expiration      string `xml:"Expiration"` // RFC3339
}

type stsAssumedRoleUser struct {
	Arn           string `xml:"Arn"`
	AssumedRoleID string `xml:"AssumedRoleId"`
}

type stsResponseMetadata struct {
	RequestID string `xml:"RequestId"`
}

// STSHandler handles the STS AssumeRole endpoint (POST /).
type STSHandler struct {
	mu      sync.Mutex
	assumeQ []queueItem
}

// QueueAssumeRole enqueues a successful AssumeRole response.
func (h *STSHandler) QueueAssumeRole(r AssumeRoleResult) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.assumeQ = append(h.assumeQ, queueItem{status: http.StatusOK, body: r})
}

// QueueAssumeRoleError enqueues an error response for AssumeRole.
func (h *STSHandler) QueueAssumeRoleError(status int, msg string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.assumeQ = append(h.assumeQ, queueItem{status: status, body: msg})
}

func (h *STSHandler) handleSTS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.mu.Lock()
	item, found := dequeue(&h.assumeQ)
	h.mu.Unlock()

	if !found {
		http.Error(w, "no queued STS responses", http.StatusInternalServerError)
		return
	}
	if item.status != http.StatusOK {
		w.WriteHeader(item.status)
		if msg, isStr := item.body.(string); isStr {
			fmt.Fprint(w, stsErrorXML(msg, item.status))
		}
		return
	}

	creds, ok := item.body.(AssumeRoleResult)
	if !ok {
		http.Error(w, "internal: wrong body type", http.StatusInternalServerError)
		return
	}

	assumedRoleID := "AROATEST"
	if creds.SessionName != "" {
		assumedRoleID = "AROATEST:" + creds.SessionName
	}

	resp := stsAssumeRoleResponse{
		AssumeRoleResult: stsAssumeRoleResult{
			Credentials: stsCredentials{
				AccessKeyID:     creds.AccessKeyID,
				SecretAccessKey: creds.SecretAccessKey,
				SessionToken:    creds.SessionToken,
				Expiration:      creds.Expiration.UTC().Format(time.RFC3339),
			},
			AssumedRoleUser: stsAssumedRoleUser{
				Arn:           creds.RoleARN,
				AssumedRoleID: assumedRoleID,
			},
		},
		ResponseMetadata: stsResponseMetadata{RequestID: "test-request-id"},
	}

	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(http.StatusOK)
	_ = xml.NewEncoder(w).Encode(resp)
}

func stsErrorXML(msg string, _ int) string {
	return fmt.Sprintf(`<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Code>AccessDenied</Code><Message>%s</Message></Error><RequestId>test-request-id</RequestId></ErrorResponse>`, msg)
}

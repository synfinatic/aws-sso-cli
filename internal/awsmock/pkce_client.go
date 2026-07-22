//go:build e2etests

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
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/synfinatic/aws-sso-cli/internal/sso/oidc"
)

// PKCECallbackClient wraps an oidc.Client and overrides StartPKCEAuthCodeFlow to
// automatically deliver the browser redirect callback, enabling headless PKCE tests.
// WaitForPKCECallback is the embedded client's real implementation, which owns and
// closes the caller-supplied listener.
type PKCECallbackClient struct {
	oidc.Client
	authCode string
}

// NewPKCECallbackClient wraps client so that StartPKCEAuthCodeFlow spawns a goroutine
// that delivers the PKCE callback to the loopback listener.
func NewPKCECallbackClient(client oidc.Client, authCode string) *PKCECallbackClient {
	return &PKCECallbackClient{Client: client, authCode: authCode}
}

// StartPKCEAuthCodeFlow calls the underlying implementation, then fires a goroutine
// that delivers the authorization code to the WaitForPKCECallback listener.
func (c *PKCECallbackClient) StartPKCEAuthCodeFlow(ctx context.Context, in oidc.StartPKCEAuthCodeInput) (oidc.PKCEAuthCodeFlow, error) {
	flow, err := c.Client.StartPKCEAuthCodeFlow(ctx, in)
	if err != nil {
		return flow, err
	}

	redirectURI := in.RedirectURI
	state := flow.State
	authCode := c.authCode

	go func() {
		callbackURL := fmt.Sprintf("%s?code=%s&state=%s", redirectURI, authCode, state)
		// Single immediate request, no retries: the callback listener is bound
		// before StartPKCEAuthCodeFlow is called, so the kernel queues this
		// connection until the server starts serving. If the pre-bind ever
		// regresses, this request fails and the test times out.
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, callbackURL, nil) //nolint:gosec
		if err != nil {
			return
		}
		httpClient := &http.Client{Timeout: 2 * time.Second}
		resp, err := httpClient.Do(req)
		if err != nil {
			return
		}
		_ = resp.Body.Close()
	}()

	return flow, nil
}

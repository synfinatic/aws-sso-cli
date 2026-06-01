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
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/synfinatic/aws-sso-cli/internal/sso/oidc"
)

// PKCECallbackClient wraps an oidc.Client and overrides StartPKCEAuthCodeFlow to
// automatically deliver the browser redirect callback, enabling headless PKCE tests.
type PKCECallbackClient struct {
	oidc.Client
	authCode string
}

// NewPKCECallbackClient wraps client so that StartPKCEAuthCodeFlow spawns a goroutine
// that delivers the PKCE callback to the loopback listener after a short delay.
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
		httpClient := &http.Client{Timeout: 2 * time.Second}
		// Retry until the loopback listener is ready (WaitForPKCECallback binds it just
		// after StartPKCEAuthCodeFlow returns, so the first few attempts may fail on load).
		for range 20 {
			time.Sleep(25 * time.Millisecond)
			req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet, callbackURL, nil) //nolint:gosec
			if reqErr != nil {
				return
			}
			resp, doErr := httpClient.Do(req)
			if doErr != nil {
				continue
			}
			_ = resp.Body.Close()
			return
		}
	}()

	return flow, nil
}

package client

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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	"github.com/synfinatic/aws-sso-cli/internal/logger"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

var log *logger.Logger

func init() {
	log = logger.GetLogger()
}

type ECSClient struct {
	server      string
	authToken   string
	loadUrl     string
	loadSlotUrl string
	profileUrl  string
	listUrl     string
	client      *http.Client
}

func NewECSClient(server, authToken, certChain string) *ECSClient {
	var client *http.Client = &http.Client{}
	var proto string = "http"
	var err error

	if certChain != "" {
		proto = "https"
		client, err = NewHTTPClient(certChain)
		if err != nil {
			panic(fmt.Sprintf("unable to load SSL certificate: %s", err.Error()))
		}
	}

	if authToken == "" {
		log.Warnf("no auth token provided, ECS server communication will be unauthenticated")
	}
	if certChain == "" {
		log.Warnf("no SSL cert provided, ECS server communication will be unencrypted")
	}

	hostPort := strings.Split(server, ":")
	if len(hostPort) != 2 || hostPort[0] == "" || hostPort[1] == "" {
		panic(fmt.Sprintf("invalid --server address: %s", server))
	}

	port, err := strconv.Atoi(hostPort[1])
	if err != nil || port < 1 || port > 65535 {
		panic(fmt.Sprintf("invalid --server port: %s", hostPort[1]))
	}

	return &ECSClient{
		server:      server,
		client:      client,
		authToken:   authToken,
		loadUrl:     fmt.Sprintf("%s://%s/", proto, server),
		loadSlotUrl: fmt.Sprintf("%s://%s%s", proto, server, ecs.SLOT_ROUTE),
		profileUrl:  fmt.Sprintf("%s://%s%s", proto, server, ecs.PROFILE_ROUTE),
		listUrl:     fmt.Sprintf("%s://%s%s", proto, server, ecs.SLOT_ROUTE),
	}
}

func (c *ECSClient) LoadUrl(profile string) string {
	if profile == "" {
		return c.loadUrl
	}
	return c.loadSlotUrl + "/" + url.PathEscape(profile)
}

func (c *ECSClient) ProfileUrl() string {
	return c.profileUrl
}

func (c *ECSClient) ListUrl() string {
	return c.listUrl
}

func (c *ECSClient) newRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", ecs.CHARSET_JSON)
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}
	log.Debugf("http req: %s", req.URL.String())
	return req, nil
}

func (c *ECSClient) SubmitCreds(creds *storage.RoleCredentials, profile string, slotted bool) error {
	log.Debugf("loading %s in a slot: %v", profile, slotted)
	cr := ecs.ECSClientRequest{
		Creds:       creds,
		ProfileName: profile,
	}
	j, _ := json.Marshal(cr)

	var path string
	if slotted {
		path = profile
	}

	req, _ := c.newRequest(http.MethodPut, c.LoadUrl(path), bytes.NewBuffer(j))
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	return checkDoResponse(resp)
}

func (c *ECSClient) GetProfile() (ecs.ListProfilesResponse, error) {
	lpr := ecs.ListProfilesResponse{}
	req, _ := c.newRequest(http.MethodGet, c.ProfileUrl(), nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return lpr, err
	}

	if err := checkDoResponse(resp); err != nil {
		return lpr, err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return lpr, err
	}

	if err = json.Unmarshal(body, &lpr); err != nil {
		return lpr, err
	}
	log.Debugf("resp: %s", spew.Sdump(lpr))

	return lpr, nil
}

// ListProfiles returns a list of profiles that are loaded into slots
func (c *ECSClient) ListProfiles() ([]ecs.ListProfilesResponse, error) {
	lpr := []ecs.ListProfilesResponse{}
	req, _ := c.newRequest(http.MethodGet, c.ListUrl(), nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return lpr, err
	}

	if err := checkDoResponse(resp); err != nil {
		return lpr, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return lpr, err
	}

	if err = json.Unmarshal(body, &lpr); err != nil {
		return lpr, err
	}
	log.Debugf("resp: %s", spew.Sdump(lpr))

	return lpr, nil
}

func (c *ECSClient) Delete(profile string) error {
	req, _ := c.newRequest(http.MethodDelete, c.LoadUrl(profile), bytes.NewBuffer([]byte("")))

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	return checkDoResponse(resp)
}

func checkDoResponse(resp *http.Response) error {
	if resp.StatusCode < 200 || resp.StatusCode > 200 {
		return fmt.Errorf("ECS Server HTTP error: %s", resp.Status)
	}
	return nil
}

// NewHTTPClient creates a new HTTP client with the provided cert chain
// preloaded into the system cert pool
func NewHTTPClient(certChain string) (*http.Client, error) {
	rootCAs, err := x509.SystemCertPool()
	if rootCAs == nil || err != nil {
		rootCAs = x509.NewCertPool()
	}

	// append our cert to the pool
	if ok := rootCAs.AppendCertsFromPEM([]byte(certChain)); !ok {
		return nil, fmt.Errorf("unable to append cert to pool")
	}

	// Trust the augmented cert pool in our client
	config := &tls.Config{
		// InsecureSkipVerify: true,
		RootCAs:    rootCAs,
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}
	tr := &http.Transport{TLSClientConfig: config}
	return &http.Client{Transport: tr}, nil
}

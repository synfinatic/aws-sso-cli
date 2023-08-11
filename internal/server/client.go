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
 */

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/davecgh/go-spew/spew"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

type Client struct {
	port int
}

func NewClient(port int) *Client {
	return &Client{
		port: port,
	}
}

func (c *Client) LoadUrl(profile string) string {
	if profile == "" {
		return fmt.Sprintf("http://localhost:%d%s", c.port, CREDS_ROUTE)
	}
	return fmt.Sprintf("http://localhost:%d%s?profile=%s", c.port, CREDS_ROUTE, url.QueryEscape(profile))
}

func (c *Client) ProfileUrl() string {
	return fmt.Sprintf("http://localhost:%d%s", c.port, PROFILE_ROUTE)
}

type ClientRequest struct {
	Creds       *storage.RoleCredentials `json:"Creds"`
	ProfileName string                   `json:"ProfileName"`
}

func (c *Client) SubmitCreds(creds *storage.RoleCredentials, profile string, slotted bool) error {
	log.Debugf("loading %s in a slot: %v", profile, slotted)
	cr := ClientRequest{
		Creds:       creds,
		ProfileName: profile,
	}
	j, err := json.Marshal(cr)
	if err != nil {
		return err
	}
	var path string
	if slotted {
		path = profile
	}
	req, err := http.NewRequest(http.MethodPut, c.LoadUrl(path), bytes.NewBuffer(j))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", CHARSET_JSON)
	client := &http.Client{}
	_, err = client.Do(req)
	return err
}

func (c *Client) GetProfile() (string, error) {
	req, err := http.NewRequest(http.MethodGet, c.ProfileUrl(), bytes.NewBuffer([]byte("")))
	if err != nil {
		return "", err
	}

	client := &http.Client{}
	req.Header.Set("Content-Type", CHARSET_JSON)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	m := map[string]string{}
	err = json.Unmarshal(body, &m)
	if err != nil {
		return "", err
	}
	log.Debugf("resp: %s", spew.Sdump(m))

	return m["profile"], nil
}

func (c *Client) Delete(profile string) error {
	req, err := http.NewRequest(http.MethodDelete, c.LoadUrl(profile), bytes.NewBuffer([]byte("")))
	if err != nil {
		return err
	}

	client := &http.Client{}
	req.Header.Set("Content-Type", CHARSET_JSON)
	if err != nil {
		return err
	}
	_, err = client.Do(req)
	return err
}

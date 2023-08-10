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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

type Client struct {
	port int
}

func NewClient(ctx context.Context, port int) (*Client, error) {
	return &Client{
		port: port,
	}, nil
}

func (c *Client) LoadUrl() string {
	return fmt.Sprintf("http://localhost:%d/load-creds", c.port)
}

func (c *Client) SubmitCreds(creds *storage.RoleCredentials) error {
	j, err := json.Marshal(creds)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut, c.LoadUrl(), bytes.NewBuffer(j))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("client error: %s", err.Error())
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	fmt.Printf("%s", body)
	return nil
}

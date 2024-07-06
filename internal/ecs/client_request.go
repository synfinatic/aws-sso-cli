package ecs

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
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/synfinatic/aws-sso-cli/internal/storage"
)

type ECSClientRequest struct {
	Creds       *storage.RoleCredentials `json:"Creds"`
	ProfileName string                   `json:"ProfileName"`
}

func (cr *ECSClientRequest) Validate() error {
	if cr.ProfileName == "" {
		return fmt.Errorf("Missing ProfileName")
	}
	if cr.Creds == nil {
		return fmt.Errorf("Missing Creds block")
	}
	return cr.Creds.Validate()
}

// ReadClientRequest unmarshals the client's request into our ClientRequest struct
// used to load new credentials into the server
func ReadClientRequest(r *http.Request) (*ECSClientRequest, error) {
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return &ECSClientRequest{}, fmt.Errorf("reading body: %s", err.Error())
	}
	req := &ECSClientRequest{}
	if err = json.Unmarshal(body, req); err != nil {
		return &ECSClientRequest{}, fmt.Errorf("parsing json: %s", err.Error())
	}

	return req, req.Validate()
}

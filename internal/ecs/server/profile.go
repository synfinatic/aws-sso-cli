package server

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
	"net/http"

	"github.com/synfinatic/aws-sso-cli/internal/ecs"
)

type ProfileHandler struct {
	ecs *EcsServer
}

func (p ProfileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		p.Get(w, r)

	default:
		log.Error("Invalid request", "url", r.URL.String())
		ecs.Invalid(w)
	}
}

func (p ProfileHandler) Get(w http.ResponseWriter, r *http.Request) {
	// get the details of the default profile
	log.Debug("fetching default profile")
	if p.ecs.DefaultCreds.ProfileName == "" {
		ecs.Unavailable(w)
		return
	}

	if p.ecs.DefaultCreds.Creds.Expired() {
		ecs.Expired(w)
		return
	}

	ecs.WriteListProfileResponse(w, ecs.NewListProfileRepsonse(p.ecs.DefaultCreds))
}

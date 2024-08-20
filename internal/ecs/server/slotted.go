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
	"net/url"
	"strings"

	"github.com/synfinatic/aws-sso-cli/internal/ecs"
)

type SlottedHandler struct {
	ecs *EcsServer
}

func (p SlottedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		p.Get(w, r)
	case http.MethodPut:
		p.Put(w, r)
	case http.MethodDelete:
		p.Delete(w, r)
	default:
		log.Error("Invalid request", "url", r.URL.String())
		ecs.Invalid(w)
	}
}

func (p *SlottedHandler) Get(w http.ResponseWriter, r *http.Request) {
	profile := GetProfileName(r.URL)
	switch profile {
	case "":
		lpr := p.ecs.ListSlottedCreds()
		ecs.WriteListProfilesResponse(w, lpr)

	default:
		creds, err := p.ecs.GetSlottedCreds(profile)
		if err != nil {
			ecs.Unavailable(w)
			return
		}
		ecs.WriteCreds(w, creds.Creds)
	}
}

func (p *SlottedHandler) Put(w http.ResponseWriter, r *http.Request) {
	creds, err := ecs.ReadClientRequest(r)
	if err != nil {
		ecs.InternalServerErrror(w, err)
		return
	}

	if err := p.ecs.PutSlottedCreds(creds); err != nil {
		ecs.InternalServerErrror(w, err)
		return
	}

	ecs.OK(w)
}

func (p *SlottedHandler) Delete(w http.ResponseWriter, r *http.Request) {
	profile := GetProfileName(r.URL)
	if err := p.ecs.DeleteSlottedCreds(profile); err != nil {
		ecs.Unavailable(w)
		return
	}
	ecs.OK(w)
}

// GetProfileName returns the name of the profile as defined as /slot/XXXX
func GetProfileName(u *url.URL) string {
	parts := strings.SplitN(u.Path, "/", 3)
	switch len(parts) {
	case 3:
		if parts[1] != "slot" {
			return ""
		}

		return parts[2]

	default:
		return ""
	}
}

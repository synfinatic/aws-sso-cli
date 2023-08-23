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
 *
 * This file is heavily based on that by 99designs:
 * https://github.com/99designs/aws-vault/blob/master/server/ecsserver.go
 *
 * Copyright (c) 2015 99designs
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import (
	"net/http"

	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

type DefaultHandler struct {
	ecs *EcsServer
}

func (p DefaultHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		p.Get(w, r)
	case http.MethodPut:
		p.Put(w, r)
	case http.MethodDelete:
		p.Delete(w, r)
	default:
		log.Errorf("WTF profile")
		Invalid(w)
	}
}

func (p *DefaultHandler) Get(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case DEFAULT_ROUTE:
		log.Debugf("fetching default creds")
		WriteCreds(w, p.ecs.DefaultCreds.Creds)

	case PROFILE_ROUTE:
		// get the name of the default profile
		if p.ecs.DefaultCreds.ProfileName == "" {
			Unavailable(w)
			return
		}

		if p.ecs.DefaultCreds.Creds.Expired() {
			http.NotFound(w, r)
			return
		}

		exp, _ := utils.TimeRemain(p.ecs.DefaultCreds.Creds.Expiration/1000, true)
		resp := ListProfilesResponse{
			ProfileName:  p.ecs.DefaultCreds.ProfileName,
			AccountIdPad: p.ecs.DefaultCreds.Creds.AccountIdStr(),
			RoleName:     p.ecs.DefaultCreds.Creds.RoleName,
			Expiration:   p.ecs.DefaultCreds.Creds.Expiration / 1000,
			Expires:      exp,
		}

		JSONResponse(w, resp)

	default:
		// 404
		http.NotFound(w, r)
	}
}

func (p DefaultHandler) Put(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != DEFAULT_ROUTE {
		http.NotFound(w, r)
		return
	}

	creds, err := ReadClientRequest(r)
	if err != nil {
		WriteMessage(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if creds.Creds.Expired() {
		Expired(w)
		return
	}

	p.ecs.DefaultCreds = creds
	OK(w)
}

func (p DefaultHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != DEFAULT_ROUTE {
		http.NotFound(w, r)
		return
	}

	p.ecs.DefaultCreds = &ClientRequest{
		ProfileName: "",
	}
	OK(w)
}

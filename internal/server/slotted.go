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
	"strings"
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
		log.Errorf("WTF slotted")
		Invalid(w)
	}
}

func (p *SlottedHandler) Get(w http.ResponseWriter, r *http.Request) {
	profile := GetProfileName(r)
	switch profile {
	case "":
		p.ecs.ListSlottedCreds(w, r)
	default:
		p.ecs.GetSlottedCreds(w, r, profile)
	}
}

func (p *SlottedHandler) Put(w http.ResponseWriter, r *http.Request) {
	profile := GetProfileName(r)
	p.ecs.PutSlottedCreds(w, r, profile)
	OK(w)
}

func (p *SlottedHandler) Delete(w http.ResponseWriter, r *http.Request) {
	profile := GetProfileName(r)
	p.ecs.DeleteSlottedCreds(w, r, profile)
	OK(w)
}

// GetProfileName returns the name of the profile as defined as /slot/XXXX
func GetProfileName(r *http.Request) string {
	parts := strings.SplitN(r.URL.Path, "/", 3)
	profile := ""
	if len(parts) > 2 {
		profile = parts[2]
	}
	log.Debugf("parsed profile name: %s", profile)
	return profile
}

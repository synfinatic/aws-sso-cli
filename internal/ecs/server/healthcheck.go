package server

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
	"encoding/json"
	"net/http"
	"strings"

	"github.com/synfinatic/aws-sso-cli/internal/ecs"
)

type HealthCheckHandler struct {
	ecs *EcsServer
}

type healthCheckResponse struct {
	Status  string `json:"status"`
	Profile string `json:"profile,omitempty"`
	Expires string `json:"expires,omitempty"`
}

func (h HealthCheckHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		log.Error("Invalid request", "method", r.Method, "url", r.URL.String())
		ecs.Invalid(w)
		return
	}

	// strip "/healthcheck" prefix, leaving "" or "/slot/<profile>"
	suffix := strings.TrimPrefix(r.URL.Path, ecs.HEALTHCHECK_ROUTE)
	suffix = strings.TrimSuffix(suffix, "/")

	if suffix == "" {
		h.getDefault(w)
		return
	}

	// expect "/slot/<profile>"
	parts := strings.SplitN(suffix, "/", 3)
	if len(parts) == 3 && parts[1] == "slot" && parts[2] != "" {
		h.getSlot(w, parts[2])
		return
	}

	ecs.Invalid(w)
}

func (h HealthCheckHandler) getDefault(w http.ResponseWriter) {
	creds := h.ecs.DefaultCreds
	if creds.ProfileName == "" {
		writeHealthCheck(w, healthCheckResponse{Status: "no credentials loaded"}, http.StatusServiceUnavailable)
		return
	}
	if creds.Creds.Expired() {
		writeHealthCheck(w, healthCheckResponse{Status: "credentials expired"}, http.StatusServiceUnavailable)
		return
	}
	writeHealthCheck(w, healthCheckResponse{
		Status:  "ok",
		Profile: creds.ProfileName,
		Expires: creds.Creds.ExpireString(),
	}, http.StatusOK)
}

func (h HealthCheckHandler) getSlot(w http.ResponseWriter, profile string) {
	creds, err := h.ecs.GetSlottedCreds(profile)
	if err != nil {
		writeHealthCheck(w, healthCheckResponse{Status: "slot not found"}, http.StatusServiceUnavailable)
		return
	}
	if creds.Creds.Expired() {
		writeHealthCheck(w, healthCheckResponse{Status: "credentials expired"}, http.StatusServiceUnavailable)
		return
	}
	writeHealthCheck(w, healthCheckResponse{
		Status:  "ok",
		Profile: creds.ProfileName,
		Expires: creds.Creds.ExpireString(),
	}, http.StatusOK)
}

func writeHealthCheck(w http.ResponseWriter, resp healthCheckResponse, statusCode int) {
	w.Header().Set("Content-Type", ecs.CHARSET_JSON)
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(resp)
}

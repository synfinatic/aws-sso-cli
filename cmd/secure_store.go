package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021 Aaron Turner  <synfinatic at gmail dot com>
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
	"time"
)

const (
	CACHE_TTL = 60 * 60 * 24 // 1 day in seconds
)

// Define the interface for storing our AWS SSO data
type SecureStorage interface {
	SaveRegisterClientData(string, RegisterClientData) error
	GetRegisterClientData(string, *RegisterClientData) error
	DeleteRegisterClientData(string) error

	SaveCreateTokenResponse(string, CreateTokenResponse) error
	GetCreateTokenResponse(string, *CreateTokenResponse) error
	DeleteCreateTokenResponse(string) error

	SaveRoles(map[string][]RoleInfo) error
	GetRoles(*map[string][]RoleInfo) error
	GetRolesExpired() bool
	DeleteRoles() error
}

type RoleCache struct {
	CreatedAt int64                 `json:"CreatedAt"`
	Roles     map[string][]RoleInfo `json:"Roles"`
}

// Returns true or false if the RoleInfoCache has expired
func (rc *RoleCache) Expired() bool {
	if rc.CreatedAt+CACHE_TTL < time.Now().Unix() {
		return true
	}
	return false
}

// Converts the map of RoleInfo into a cache
func RoleInfoCache(roles map[string][]RoleInfo) RoleCache {
	cache := RoleCache{
		CreatedAt: time.Now().Unix(),
		Roles:     roles,
	}
	return cache
}

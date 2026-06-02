package main

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
	sso "github.com/synfinatic/aws-sso-cli/internal/sso"
	ssocache "github.com/synfinatic/aws-sso-cli/internal/sso/cache"
)

// newMinimalSettings constructs a *sso.Settings backed by the supplied cache.
// Useful in tests that need a RunContext.Settings without a real config file.
func newMinimalSettings(c *ssocache.Cache) *sso.Settings {
	return &sso.Settings{Cache: c}
}

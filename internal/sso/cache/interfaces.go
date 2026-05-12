package cache

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

// SettingsReader is the interface that provides cache-relevant configuration
// from Settings without exposing the full concrete type.
// *sso.Settings satisfies this interface.
type SettingsReader interface {
	GetCacheFile() string
	GetDefaultSSO() string
	GetHistoryLimit() int64
	GetHistoryMinutes() int64
	GetProfileFormat() string
	GetEnvVarTags() map[string]string
	GetThreads() int
	GetSSONames() []string
}

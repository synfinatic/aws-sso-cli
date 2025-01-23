package config

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2025 Aaron Turner  <synfinatic at gmail dot com>
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
	"fmt"
	"os"

	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

const (
	OLD_CONFIG_DIR      = "~/.aws-sso"
	CONFIG_FILE         = "%s/config.yaml"
	JSON_STORE_FILE     = "%s/store.json"
	INSECURE_CACHE_FILE = "%s/cache.json"
)

// ConfigDir returns the path to the config directory
func ConfigDir(expand bool) string {
	path := "~/.config/aws-sso" // default XDG path is default

	// check if the user has a custom XDG_CONFIG_HOME
	xdgPath, ok := os.LookupEnv("XDG_CONFIG_HOME")
	if ok {
		// fixup the path if it's the default, otherwise our tests are a disaster
		if xdgPath == fmt.Sprintf("%s/.config", os.Getenv("HOME")) {
			xdgPath = "~/.config"
		}
		path = fmt.Sprintf("%s/aws-sso", xdgPath)
	}

	// check if the user has an old config directory which overrides
	// the XDG_CONFIG_HOME
	fi, err := os.Stat(utils.GetHomePath(OLD_CONFIG_DIR))
	if err == nil && fi.IsDir() {
		path = OLD_CONFIG_DIR
	}

	if expand {
		path = utils.GetHomePath(path)
	}
	return path
}

// ConfigFile returns the path to the config file
func ConfigFile(expand bool) string {
	return fmt.Sprintf(CONFIG_FILE, ConfigDir(expand))
}

// JsonStoreFile returns the path to the JSON store file
func JsonStoreFile(expand bool) string {
	return fmt.Sprintf(JSON_STORE_FILE, ConfigDir(expand))
}

// InsecureCacheFile returns the path to the insecure cache file
func InsecureCacheFile(expand bool) string {
	return fmt.Sprintf(INSECURE_CACHE_FILE, ConfigDir(expand))
}

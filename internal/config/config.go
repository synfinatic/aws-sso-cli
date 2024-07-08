package config

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
	"fmt"
	"os"

	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

const (
	OLD_CONFIG_DIR      = "~/.aws-sso"
	CONFIG_DIR          = "~/.config/aws-sso"
	CONFIG_FILE         = "%s/config.yaml"
	JSON_STORE_FILE     = "%s/store.json"
	INSECURE_CACHE_FILE = "%s/cache.json"
)

func ConfigDir(expand bool) string {
	var path string
	fi, err := os.Stat(utils.GetHomePath(OLD_CONFIG_DIR))
	if err == nil && fi.IsDir() {
		path = OLD_CONFIG_DIR
	} else {
		path = CONFIG_DIR
	}
	if expand {
		path = utils.GetHomePath(path)
	}
	return path
}

// ConfigFile returns the path to the config file
func ConfigFile(expand bool) string {
	var path string
	fi, err := os.Stat(utils.GetHomePath(OLD_CONFIG_DIR))
	fmt.Printf("fi: %v, err: %v\n", fi, err)
	if err == nil && fi.IsDir() {
		path = fmt.Sprintf(CONFIG_FILE, OLD_CONFIG_DIR)
	} else {
		path = fmt.Sprintf(CONFIG_FILE, CONFIG_DIR)
	}
	if expand {
		path = utils.GetHomePath(path)
	}
	return path
}

// JsonStoreFile returns the path to the JSON store file
func JsonStoreFile(expand bool) string {
	var path string
	fi, err := os.Stat(utils.GetHomePath(OLD_CONFIG_DIR))
	if err == nil && fi.IsDir() {
		path = fmt.Sprintf(JSON_STORE_FILE, OLD_CONFIG_DIR)
	} else {
		path = fmt.Sprintf(JSON_STORE_FILE, CONFIG_DIR)
	}
	if expand {
		path = utils.GetHomePath(path)
	}
	return path
}

// InsecureCacheFile returns the path to the insecure cache file
func InsecureCacheFile(expand bool) string {
	var path string
	fi, err := os.Stat(utils.GetHomePath(OLD_CONFIG_DIR))
	if err == nil && fi.IsDir() {
		path = fmt.Sprintf(INSECURE_CACHE_FILE, OLD_CONFIG_DIR)
	} else {
		path = fmt.Sprintf(INSECURE_CACHE_FILE, CONFIG_DIR)
	}
	if expand {
		path = utils.GetHomePath(path)
	}
	return path
}

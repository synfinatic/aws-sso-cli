package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021 Aaron Turner  <aturner at synfin dot net>
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
	"reflect"
	"strings"

	yaml "github.com/goccy/go-yaml"
	"github.com/synfinatic/onelogin-aws-role/utils"
)

type ConfigFile struct {
	SSO     map[string]SSOConfig `yaml:"sso"`
	Region  string               `yaml:"region,omitempty"`
	Browser string               `yaml:"browser,omitempty"`
}

type SSOConfig struct {
	StartUrl  string `yaml:"start_url"`
	SSORegion string `yaml:"sso_region"`
	Region    string `yaml:"region,omitempty"`
}

func (c *SSOConfig) IsValid() bool {
	return c.StartUrl != "" && c.SSORegion != ""
}

type SSOConfigList struct {
	Name      string `header:"Name"`
	StartUrl  string `header:"Start Url"`
	SSORegion string `header:"SSO Region"`
	Region    string `header:"AWS Default Region"`
}

func (s SSOConfigList) GetHeader(fieldName string) (string, error) {
	v := reflect.ValueOf(s)
	return utils.GetHeaderTag(v, fieldName)
}

// Returns the config file path.
func GetPath(path string) string {
	return strings.Replace(path, "~", os.Getenv("HOME"), 1)
}

// Loads our config file at the given path
func LoadConfigFile(path string) (*ConfigFile, error) {
	fullpath := GetPath(path)
	info, err := os.Stat(fullpath)
	if err != nil {
		return nil, fmt.Errorf("Unable to stat %s: %s", fullpath, err.Error())
	}

	file, err := os.Open(fullpath)
	if err != nil {
		return nil, fmt.Errorf("Unable to open %s: %s", fullpath, err.Error())
	}

	defer file.Close()

	buf := make([]byte, info.Size())
	_, err = file.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("Unable to read %s: %s", fullpath, err.Error())
	}

	c := ConfigFile{}
	err = yaml.Unmarshal(buf, &c)
	if err != nil {
		return nil, fmt.Errorf("Error parsing %s: %s", fullpath, err.Error())
	}

	return &c, nil
}

// returns a flat SSO Config list
func (cf *ConfigFile) GetSSOConfigList() []SSOConfigList {
	retval := []SSOConfigList{}
	for name, config := range cf.SSO {
		retval = append(retval, SSOConfigList{
			Name:      name,
			StartUrl:  config.StartUrl,
			SSORegion: config.SSORegion,
			Region:    config.Region,
		})
	}
	return retval
}

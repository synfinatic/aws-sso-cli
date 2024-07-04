package ecs

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
 */

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	CONTAINER_MOUNT_POINT = "/app/.aws-sso/mnt"
	CONTAINER_NAMED_FILE  = "/app/.aws-sso/mnt/docker-ecs"
	HOST_MOUNT_POINT_FMT  = "%s/.aws-sso/mnt"
	HOST_NAMED_FILE_FMT   = "%s/.aws-sso/mnt/docker-ecs"
)

type ECSFileMode int

const (
	READ_ONLY  ECSFileMode = ECSFileMode(os.O_RDONLY)
	WRITE_ONLY ECSFileMode = ECSFileMode(os.O_WRONLY | os.O_CREATE | os.O_TRUNC)
)

type ECSSecurity struct {
	PrivateKey  string `json:"privateKey"`
	CertChain   string `json:"certChain"`
	BearerToken string `json:"bearerToken"`
}

func SecurityFilePath(mode ECSFileMode) string {
	switch mode {
	case READ_ONLY:
		return CONTAINER_NAMED_FILE
	case WRITE_ONLY:
		home := os.Getenv("HOME")
		if home == "" {
			panic("HOME environment variable not set")
		}

		return fmt.Sprintf(HOST_NAMED_FILE_FMT, home)
	default:
		return ""
	}
}

// WriteSecurityConfig writes the security configuration to a regular file
// since the ECS container can't read from named pipes when the host is Windows
// or MacOS
func WriteSecurityConfig(f *os.File, privateKey, certChain, bearerToken string) error {
	ecsSecurity := &ECSSecurity{
		PrivateKey:  privateKey,
		CertChain:   certChain,
		BearerToken: bearerToken,
	}

	data, _ := json.Marshal(ecsSecurity)
	_, err := f.Write(data)
	return err
}

// ReadSecurityConfig reads the security configuration from a regular file
// and then deletes it.
func ReadSecurityConfig(f *os.File) (*ECSSecurity, error) {
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	ecsSecurity := &ECSSecurity{}
	err = json.Unmarshal(data, ecsSecurity)
	if err != nil {
		return nil, err
	}

	return ecsSecurity, nil
}

var testOpenSecurityFilePath string = ""

// OpenSecurityFile opens the security file for reading (FILE_READ) or writing (FILE_WRITE)
func OpenSecurityFile(mode ECSFileMode) (*os.File, error) {
	var f *os.File
	var err error

	filePath := SecurityFilePath(mode)

	// hack for unit tests
	if testOpenSecurityFilePath != "" {
		filePath = testOpenSecurityFilePath
	}

	switch mode {
	case READ_ONLY:
		if f, err = os.Open(filePath); err != nil {
			return nil, fmt.Errorf("unable to open security file: %w", err)
		}
	case WRITE_ONLY:
		if _, err := os.Stat(filePath); err != nil {
			if err := os.MkdirAll(filepath.Dir(filePath), 0700); err != nil {
				return nil, fmt.Errorf("unable to open security file: %w", err)
			}
		}

		if f, err = os.OpenFile(filePath, int(WRITE_ONLY), 0600); err != nil {
			return nil, fmt.Errorf("unable to open security file: %w", err)
		}
	}
	return f, nil
}

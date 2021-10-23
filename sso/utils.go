package sso

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
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
)

// ensures the given directory exists for the filename
// used by JsonStore and InsecureStore
func ensureDirExists(filename string) error {
	storeDir := path.Dir(filename)
	f, err := os.Open(storeDir)
	if err != nil {
		err = os.MkdirAll(storeDir, 0700)
		if err != nil {
			return fmt.Errorf("Unable to create %s: %s", storeDir, err.Error())
		}
	}
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("Unable to stat %s: %s", storeDir, err.Error())
	}
	if !info.IsDir() {
		return fmt.Errorf("%s exists and is not a directory!", storeDir)
	}
	return nil
}

// Creates an AWS ARN for a role
func MakeRoleARN(account int64, name string) string {
	return fmt.Sprintf("arn:aws:iam:%d:role/%s", account, name)
}

// GetRoleParts returns the accountId & rolename for an ARN
func GetRoleParts(arn string) (int64, string, error) {
	var accountId int64
	var role string
	s := strings.Split(arn, ":")
	if len(s) == 2 {
		// Short account:role format
		id, err := strconv.ParseInt(s[0], 10, 64)
		if err != nil {
			return 0, "", err
		}
		accountId = id
		role = s[1]
	} else if len(s) == 5 {
		id, err := strconv.ParseInt(s[3], 10, 64)
		if err != nil {
			return 0, "", err
		}
		accountId = id
		s = strings.Split(s[4], "/")
		if len(s) != 2 {
			return 0, "", fmt.Errorf("Invalid ARN: %s", arn)
		}
		role = s[1]
	} else {
		return 0, "", fmt.Errorf("Invalid ARN: %s", arn)
	}

	return accountId, role, nil
}

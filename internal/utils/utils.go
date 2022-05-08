package utils

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
	// "bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const MAX_AWS_ACCOUNTID = 999999999999

// GetHomePath returns the absolute path of the provided path with the first ~
// replaced with the location of the users home directory and the path rewritten
// for the host operating system
func GetHomePath(path string) string {
	// easiest to just manually replace our separator rather than relying on filepath.Join()
	sep := fmt.Sprintf("%c", os.PathSeparator)
	p := strings.ReplaceAll(path, "/", sep)
	if strings.HasPrefix(p, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			log.WithError(err).Fatalf("Unable to GetHomePath(%s)", path)
		}

		p = strings.Replace(p, "~", home, 1)
	}
	return filepath.Clean(p)
}

// ParseRoleARN parses an ARN representing a role in long or short format
func ParseRoleARN(arn string) (int64, string, error) {
	s := strings.Split(arn, ":")
	var accountid, role string
	switch len(s) {
	case 2:
		// short account:Role format
		accountid = s[0]
		role = s[1]
	case 6:
		// long format for arn:aws:iam::XXXXXXXXXX:role/YYYYYYYY
		accountid = s[4]
		s = strings.Split(s[5], "/")
		if len(s) != 2 {
			return 0, "", fmt.Errorf("Unable to parse ARN: %s", arn)
		}
		role = s[1]
	default:
		return 0, "", fmt.Errorf("Unable to parse ARN: %s", arn)
	}

	aId, err := strconv.ParseInt(accountid, 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("Unable to parse ARN: %s", arn)
	}
	if aId < 0 {
		return 0, "", fmt.Errorf("Invalid AccountID: %d", aId)
	}
	return aId, role, nil
}

// ParseUserARN parses an ARN representing a user in long or short format
func ParseUserARN(arn string) (int64, string, error) {
	return ParseRoleARN(arn)
}

// MakeRoleARN create an IAM Role ARN using an int64 for the account
func MakeRoleARN(account int64, name string) string {
	a, err := AccountIdToString(account)
	if err != nil {
		log.WithError(err).Panicf("Unable to MakeRoleARN")
	}
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", a, name)
}

// MakeUserARN create an IAM User ARN using an int64 for the account
func MakeUserARN(account int64, name string) string {
	a, err := AccountIdToString(account)
	if err != nil {
		log.WithError(err).Panicf("Unable to MakeUserARN")
	}
	return fmt.Sprintf("arn:aws:iam::%s:user/%s", a, name)
}

// MakeRoleARNs creates an IAM Role ARN using a string for the account and role
func MakeRoleARNs(account, name string) string {
	x, err := AccountIdToInt64(account)
	if err != nil {
		log.WithError(err).Panicf("Unable to AccountIdToInt64 in MakeRoleARNs")
	}

	a, _ := AccountIdToString(x)
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", a, name)
}

// ensures the given directory exists for the filename
// used by JsonStore and InsecureStore
func EnsureDirExists(filename string) error {
	storeDir := filepath.Dir(filename)
	f, err := os.Open(storeDir)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(storeDir, 0700); err != nil {
			return fmt.Errorf("Unable to create %s: %s", storeDir, err.Error())
		}
		return nil
	} else if err != nil {
		return err
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

// ParseTimeString converts a standard time string to Unix Epoch
func ParseTimeString(t string) (int64, error) {
	i, err := time.Parse("2006-01-02 15:04:05 -0700 MST", t)
	if err != nil {
		return 0, fmt.Errorf("Unable to parse %s: %s", t, err.Error())
	}
	return i.Unix(), nil
}

// Returns the MMm or HHhMMm or 'Expired' if no time remains
func TimeRemain(expires int64, space bool) (string, error) {
	d := time.Until(time.Unix(expires, 0))
	if d <= 0 {
		return "Expired", nil
	}

	s := strings.Replace(d.Round(time.Minute).String(), "0s", "", 1)
	if space {
		if strings.Contains(s, "h") {
			s = strings.Replace(s, "h", "h ", 1)
		} else {
			s = fmt.Sprintf("   %s", s)
		}
	}

	// Just return the number of MMm or HHhMMm
	return s, nil
}

// AccountIdToString returns a string version of AWS AccountID
func AccountIdToString(a int64) (string, error) {
	if a < 0 || a > MAX_AWS_ACCOUNTID {
		return "", fmt.Errorf("Invalid AWS AccountId: %d", a)
	}
	return fmt.Sprintf("%012d", a), nil
}

// AccountIdToInt64 returns an int64 version of AWS AccountID in base10
func AccountIdToInt64(a string) (int64, error) {
	x, err := strconv.ParseInt(a, 10, 64)
	if err != nil {
		return 0, err
	}
	if x < 0 {
		return 0, fmt.Errorf("Invalid AWS AccountId: %s", a)
	}
	return x, nil
}

// StrListContains returns if `str` is in the `list`
func StrListContains(str string, list []string) bool {
	for _, v := range list {
		if v == str {
			return true
		}
	}
	return false
}

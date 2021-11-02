package utils

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
	"time"

	"github.com/atotto/clipboard"
	//	log "github.com/sirupsen/logrus"
	"github.com/skratchdot/open-golang/open" // default opener
)

func GetHomePath(path string) string {
	return strings.Replace(path, "~", os.Getenv("HOME"), 1)
}

func HandleUrl(action, browser, url, pre, post string) error {
	var err error
	switch action {
	case "clip":
		err = clipboard.WriteAll(url)
		if err == nil {
			fmt.Printf("Please open URL copied to clipboard.\n")
		} else {
			err = fmt.Errorf("Unable to copy %s to clipboard: %s", url, err.Error())
		}
	case "print":
		fmt.Printf("%s%s%s", pre, url, post)
	case "open":
		if len(browser) == 0 {
			err = open.Run(url)
			browser = "default browser"
		} else {
			err = open.RunWith(url, browser)
		}
		if err != nil {
			err = fmt.Errorf("Unable to open %s with %s: %s", url, browser, err.Error())
		} else {
			fmt.Printf("Opening %s in %s\n", url, browser)
		}
	default:
		err = fmt.Errorf("Unknown --url-action option: %s", action)
	}

	return err
}

// ParseRoleARN parses an ARN representing a role in long or short format
func ParseRoleARN(arn string) (int64, string, error) {
	s := strings.Split(arn, ":")
	var accountid, role string
	if len(s) == 2 {
		// short account:Role format
		accountid = s[0]
		role = s[1]
	} else if len(s) == 5 {
		// long format for arn:aws:iam:XXXXXXXXXX:role/YYYYYYYY
		accountid = s[3]
		s = strings.Split(s[4], "/")
		if len(s) != 2 {
			return 0, "", fmt.Errorf("Unable to parse ARN: %s", arn)
		}
		role = s[1]
	} else {
		return 0, "", fmt.Errorf("Unable to parse ARN: %s", arn)
	}

	aId, err := strconv.ParseInt(accountid, 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("Unable to parse ARN: %s", arn)
	}
	return aId, role, nil
}

// Creates an AWS ARN for a role
func MakeRoleARN(account int64, name string) string {
	return fmt.Sprintf("arn:aws:iam:%012d:role/%s", account, name)
}

// ensures the given directory exists for the filename
// used by JsonStore and InsecureStore
func EnsureDirExists(filename string) error {
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

func ParseTimeString(t string) (int64, error) {
	i, err := time.Parse("2006-01-02 15:04:05 -0700 MST", t)
	if err != nil {
		return 0, fmt.Errorf("Unable to parse %s: %s", t, err.Error())
	}
	return i.Unix(), nil
}

// Returns the MMm or HHhMMm
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

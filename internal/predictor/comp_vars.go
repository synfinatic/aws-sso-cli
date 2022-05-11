package predictor

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
	"os"
	"strconv"
	"strings"
)

// getSSOFlag returns the value of -S/--sso from $COMP_LINE or empty string
func getSSOFlag() string {
	compLine, ok := os.LookupEnv("COMP_LINE")
	if !ok {
		return ""
	}

	return flagValue(compLine, []string{"-S", "--sso"})
}

// getAccountIdFlag returns the value of -A/--account from $COMP_LINE or
// -1 for none
func getAccountIdFlag() int64 {
	compLine, ok := os.LookupEnv("COMP_LINE")
	if !ok {
		return -1
	}

	aStr := flagValue(compLine, []string{"-A", "--account"})
	if aStr == "" {
		return -1
	}
	aid, _ := strconv.ParseInt(aStr, 10, 64)
	return aid
}

// getRoleFlag returns the value of -R/--role from $COMP_LINE or empty string
func getRoleFlag() string {
	compLine, ok := os.LookupEnv("COMP_LINE")
	if !ok {
		return ""
	}

	return flagValue(compLine, []string{"-R", "--role"})
}

func flagValue(line string, flags []string) string {
	var flag string
	i := 0

	// remove double spaces
	line = strings.ReplaceAll(line, "  ", "")

	// skip past our executable
	i = strings.Index(line, " ")
	if i < 0 {
		return ""
	}

	line = line[i:]

	for _, flag = range flags {
		i = strings.Index(line, flag)
		if i > 0 {
			i += len(flag)
			line = line[i:] // jump past our flag
			break
		}
	}

	// missing completely or need a space + at least 1 char
	if i < 0 || len(line) < 2 {
		return ""
	}

	line = line[1:] // eat the space

	// find the next space
	i = strings.Index(line, " ")
	if i < 0 {
		// let kongplete do the work
		return ""
	}

	// return a result
	return line[:i]
}

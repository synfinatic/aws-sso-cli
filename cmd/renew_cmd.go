package main

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
	"strconv"
	"strings"
)

type RenewCmd struct{}

func (cc *RenewCmd) Run(ctx *RunContext) error {
	accountid := os.Getenv("AWS_ACCOUNT_ID")
	role := os.Getenv("AWS_ROLE_NAME")

	if accountid == "" {
		return fmt.Errorf("Unable to refresh: AWS_ACCOUNT_ID is not set")
	}
	if role == "" {
		return fmt.Errorf("Unable to refresh: AWS_ROLE_NAME is not set")
	}

	aid, err := strconv.ParseInt(accountid, 10, 64)
	if err != nil {
		return fmt.Errorf("Unable to parse AWS_ACCOUNT_ID = %s: %s", accountid, err.Error())
	}

	awssso := doAuth(ctx)
	for k, v := range execShellEnvs(ctx, awssso, aid, role) {
		if strings.Contains(v, " ") {
			fmt.Printf("export %s=\"%s\"\n", k, v)
		} else {
			fmt.Printf("export %s=%s\n", k, v)
		}
	}
	return nil
}

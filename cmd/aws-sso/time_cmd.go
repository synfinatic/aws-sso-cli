package main

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

type TimeCmd struct{}

// AfterApply determines if SSO auth token is required
func (l TimeCmd) AfterApply(runCtx *RunContext) error {
	runCtx.Auth = AUTH_NO
	return nil
}

func (cc *TimeCmd) Run(ctx *RunContext) error {
	expires, isset := os.LookupEnv("AWS_SSO_SESSION_EXPIRATION")
	if !isset {
		return nil // no output if nothing is set
	}

	t, err := utils.ParseTimeString(expires)
	if err != nil {
		return err
	}
	exp, err := utils.TimeRemain(t, false)
	if err != nil {
		return err
	}
	fmt.Printf("%s", exp)
	return nil
}

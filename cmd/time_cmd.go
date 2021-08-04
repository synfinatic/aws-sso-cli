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
	"strings"
	"time"
)

type TimeCmd struct{}

func (cc *TimeCmd) Run(ctx *RunContext) error {
	expires, isset := os.LookupEnv("AWS_SESSION_EXPIRATION")
	if !isset {
		return nil // no output if nothing is set
	}

	t, err := time.Parse("2006-01-02 15:04:05 -0700 MST", expires)
	if err != nil {
		return fmt.Errorf("Unable to parse AWS_SESSION_EXPIRATION: %s", err.Error())
	}

	d := time.Until(t)
	if d <= 0 {
		fmt.Printf("EXPIRED")
		return nil
	}

	// Just return the number of MMm or HHhMMm
	fmt.Printf("%s", strings.Replace(d.Round(time.Minute).String(), "0s", "", 1))
	return nil
}

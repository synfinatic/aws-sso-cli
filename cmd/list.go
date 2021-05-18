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
// "fmt"

//	log "github.com/sirupsen/logrus"
//  "github.com/synfinatic/onelogin-aws-role/utils"
)

// Fields match those in FlatConfig.  Used when user doesn't have the `fields` in
// their YAML config file or provided list on the CLI
var defaultListFields = []string{
	"AccountId",
	"AccountName",
	"Role",
	"Profile",
	"Region",
	"Expires",
}

type ListCmd struct {
	Fields     []string `kong:"optional,arg,enum='AccountId,AccountName,Arn,Role,Expires,Profile,Region,SSORegion,StartUrl',help='Fields to display',default='${defaultListFields}',env=AWS_SSO_FIELDS"`
	ListFields bool     `kong:"optional,short='f',help='List available fields'"`
}

// what should this actually do?
func (cc *ListCmd) Run(ctx *RunContext) error {
	return nil
}

package config

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2026 Aaron Turner  <synfinatic at gmail dot com>
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
	"reflect"
	"strconv"

	"github.com/synfinatic/aws-sso-cli/internal/awsparse"
	"github.com/synfinatic/gotable"
)

type RoleInfo struct {
	Id           int    `yaml:"Id" json:"Id" header:"Id"`
	Arn          string `yaml:"-" json:"-" header:"Arn"`
	RoleName     string `yaml:"RoleName" json:"RoleName" header:"RoleName"`
	AccountId    string `yaml:"AccountId" json:"AccountId" header:"AccountId"`
	AccountName  string `yaml:"AccountName" json:"AccountName" header:"AccountName"`
	EmailAddress string `yaml:"EmailAddress" json:"EmailAddress" header:"EmailAddress"`
	Expires      int64  `yaml:"Expires" json:"Expires" header:"Expires"`
	Profile      string `yaml:"Profile" json:"Profile" header:"Profile"`
	Region       string `yaml:"Region" json:"Region" header:"Region"`
	SSORegion    string `header:"SSORegion"`
	StartUrl     string `header:"StartUrl"`
	Via          string `header:"Via"`
}

func (ri RoleInfo) GetHeader(fieldName string) (string, error) {
	v := reflect.ValueOf(ri)
	return gotable.GetHeaderTag(v, fieldName)
}

func (ri RoleInfo) RoleArn() string {
	a, _ := strconv.ParseInt(ri.AccountId, 10, 64)
	return awsparse.MakeRoleARN(a, ri.RoleName)
}

func (ri RoleInfo) GetAccountId64() int64 {
	i64, err := strconv.ParseInt(ri.AccountId, 10, 64)
	if err != nil {
		panic(fmt.Sprintf("Invalid AWS AccountID from AWS SSO: %s", ri.AccountId))
	}
	if i64 < 0 {
		panic(fmt.Sprintf("AWS AccountID must be >= 0: %s", ri.AccountId))
	}
	return i64
}

type AccountInfo struct {
	Id           int    `yaml:"Id" json:"Id" header:"Id"`
	AccountId    string `yaml:"AccountId" json:"AccountId" header:"AccountId"`
	AccountName  string `yaml:"AccountName" json:"AccountName" header:"AccountName"`
	EmailAddress string `yaml:"EmailAddress" json:"EmailAddress" header:"EmailAddress"`
}

func (ai AccountInfo) GetHeader(fieldName string) (string, error) {
	v := reflect.ValueOf(ai)
	return gotable.GetHeaderTag(v, fieldName)
}

func (ai AccountInfo) GetAccountId64() int64 {
	i64, err := strconv.ParseInt(ai.AccountId, 10, 64)
	if err != nil {
		panic(fmt.Sprintf("Invalid AWS AccountID from AWS SSO: %s", ai.AccountId))
	}
	if i64 < 0 {
		panic(fmt.Sprintf("AWS AccountID must be >= 0: %s", ai.AccountId))
	}
	return i64
}

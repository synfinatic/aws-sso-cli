package awssso

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2023 Aaron Turner  <synfinatic at gmail dot com>
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
	"reflect"
	"strconv"

	"github.com/synfinatic/gotable"
)

type AccountInfo struct {
	Id           int    `yaml:"Id" json:"Id" header:"Id"`
	AccountId    string `yaml:"AccountId" json:"AccountId" header:"AccountId"`
	AccountName  string `yaml:"AccountName" json:"AccountName" header:"AccountName"`
	EmailAddress string `yaml:"EmailAddress" json:"EmailAddress" header:"EmailAddress"`
}

// GetHeader is for gotable
func (ai AccountInfo) GetHeader(fieldName string) (string, error) {
	v := reflect.ValueOf(ai)
	return gotable.GetHeaderTag(v, fieldName)
}

// GetAccountId64 returns the accountId as an int64
func (ai AccountInfo) GetAccountId64() int64 {
	i64, err := strconv.ParseInt(ai.AccountId, 10, 64)
	if err != nil {
		log.WithError(err).Panicf("Invalid AWS AccountID from AWS SSO: %s", ai.AccountId)
	}
	if i64 < 0 {
		log.WithError(err).Panicf("AWS AccountID must be >= 0: %s", ai.AccountId)
	}
	return i64
}

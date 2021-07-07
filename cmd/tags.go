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
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
)

// TagsList provides the necessary struct finding all the possible tag key/values
type TagsList map[string][]string // tag key => list of values

func NewTagsList() *TagsList {
	return &TagsList{}
}

// Inserts the tag/value does not already exist
func (t *TagsList) Add(tag, v string) {
	tt := *t
	key := strings.ReplaceAll(tag, " ", "_")
	value := strings.ReplaceAll(v, " ", "_")
	if tt[key] == nil {
		tt[key] = []string{value}
		return // inserted
	}

	for _, check := range tt[key] {
		if check == value {
			return
		}
	}

	i := sort.SearchStrings(tt[tag], value)

	tt[key] = append(tt[key], "")
	copy(tt[key][i+1:], tt[key][i:])
	tt[key][i] = value
}

// AddTags inserts a map of tag/values if they do not already exist
func (t *TagsList) AddTags(tags map[string]string) {
	for tag, value := range tags {
		t.Add(tag, value)
	}
}

// Merge adds all the new tags in a to the TagsList
func (t *TagsList) Merge(a *TagsList) {
	for tag, values := range *a {
		for _, v := range values {
			t.Add(tag, v)
		}
	}
}

// RoleTags provides an interface to find roles which match a set of tags
type RoleTags struct {
	Tags map[string]map[string]string // ARN => Tag => Value
}

func NewRoleTags(a *AWSSSO, s *SSOConfig) *RoleTags {
	r := &RoleTags{
		Tags: map[string]map[string]string{},
	}
	r.addAWSSO(a)
	r.addSSOConfig(s)
	return r
}

func (r *RoleTags) addSSOConfig(s *SSOConfig) {
	roles := s.GetRoles()
	for _, role := range roles {
		// add role level tags
		for tag, value := range role.Tags {
			// go-prompt delimates on spaces, so replace with underscore
			t := strings.ReplaceAll(tag, " ", "_")
			v := strings.ReplaceAll(value, " ", "_")
			r.Tags[role.ARN][t] = v
		}

		// add any account level tags to our role
		if account, ok := s.Accounts[role.GetAccountId64()]; ok {
			for tag, value := range account.Tags {
				t := strings.ReplaceAll(tag, " ", "_")
				v := strings.ReplaceAll(value, " ", "_")
				r.Tags[role.ARN][t] = v
			}

		}
	}
}

func (r *RoleTags) addAWSSO(a *AWSSSO) {
	//	rr := *r
	accounts, err := a.GetAccounts()
	if err != nil {
		log.Fatalf("Unable to get AWS SSO accounts: %s", err.Error())
	}
	for _, account := range accounts {
		roles, err := a.GetRoles(account)
		if err != nil {
			log.Fatalf("Unable to get AWS SSO roles: %s", err.Error())
		}
		for _, role := range roles {
			arn := role.RoleArn()
			if r.Tags[arn] == nil {
				r.Tags[arn] = map[string]string{}
			}
			r.Tags[arn]["RoleName"] = role.RoleName
			r.Tags[arn]["AccountId"] = role.AccountId
			r.Tags[arn]["AccountName"] = strings.ReplaceAll(role.AccountName, " ", "_")
			r.Tags[arn]["EmailAddress"] = role.EmailAddress
		}
	}
}

// GetMatchingRoles returns the roles which match all the tags
func (r *RoleTags) GetMatchingRoles(tags map[string]string) []string {
	matches := []string{}

	for arn, roleTags := range r.Tags {
		match := map[string]bool{}
		for k, v := range tags {
			if check, ok := roleTags[k]; ok {
				if v == check {
					match[k] = true
				}
			}
		}
		if len(match) == len(tags) {
			matches = append(matches, arn)
		}
	}
	return matches
}

func (r *RoleTags) GetMatchCount(tags map[string]string) int {
	return len(r.GetMatchingRoles(tags))
}

// takes a role ARN and returns the accountid & rolename
func getAccountRole(arn string) (string, string, error) {
	s := strings.Split(arn, ":")
	if len(s) != 5 {
		return "", "", fmt.Errorf("Invalid Role ARN: %s", arn)
	}
	account := s[3]
	s = strings.Split(arn, "/")
	if len(s) != 2 {
		return "", "", fmt.Errorf("Invalid Role ARN: %s", arn)
	}
	role := s[1]
	return account, role, nil
}

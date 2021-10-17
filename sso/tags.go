package sso

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
)

// TagsList provides the necessary struct finding all the possible tag key/values
type TagsList map[string][]string // tag key => list of values

func NewTagsList() *TagsList {
	return &TagsList{}
}

// Inserts the tag/value if it does not already exist in the sorted order
func (t *TagsList) Add(tag, v string) {
	tt := *t
	if tt[tag] == nil {
		tt[tag] = []string{v}
		return // inserted
	}

	for _, check := range tt[tag] {
		if check == v {
			return // already exists
		}
	}

	i := sort.SearchStrings(tt[tag], v)

	tt[tag] = append(tt[tag], "")
	copy(tt[tag][i+1:], tt[tag][i:])
	tt[tag][i] = v
}

// AddTags inserts a map of tag/values if they do not already exist
func (t *TagsList) AddTags(tags map[string]string) {
	for tag, value := range tags {
		t.Add(tag, value)
	}
}

// Returns the list of values for the specified key
func (t *TagsList) Get(key string) []string {
	x := *t
	if v, ok := x[key]; ok {
		return v
	} else {
		return []string{}
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

// Returns a sorted unique list of tag keys, removing any keys which have already been picked
func (t *TagsList) UniqueKeys(picked []string) []string {
	keys := []string{}
	for key, _ := range *t {
		seen := false
		for _, c := range picked {
			if c == key {
				seen = true
				break
			}
		}
		if !seen {
			keys = append(keys, key)
		}
	}
	sort.Sort(sort.StringSlice(keys))
	return keys
}

// Returns a sorted unique list of tag values for the given key
func (t *TagsList) UniqueValues(key string) []string {
	x := *t
	if values, ok := x[key]; ok {
		sort.Sort(sort.StringSlice(values))
		return values
	}

	return []string{}
}

// RoleTags provides an interface to find roles which match a set of tags
type RoleTags map[string]map[string]string // ARN => TagKey => Value

func (r *RoleTags) GetRoleTags(role string) map[string]string {
	rtags := *r
	if v, ok := rtags[role]; ok {
		return v
	}
	return map[string]string{}
}

// GetMatchingRoles returns the roles which match all the tags
func (r *RoleTags) GetMatchingRoles(tags map[string]string) []string {
	matches := []string{}

	for arn, rTags := range *r {
		match := map[string]bool{}
		for k, v := range tags {
			if check, ok := rTags[k]; ok {
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

// GetPossibleMatches is like GetMatchingRoles, but takes another key
// and a list of values and it returns the unique set of all roles which
// match the base tags and all the possible combnations of key/values
func (r *RoleTags) GetPossibleUniqueRoles(tags map[string]string, key string, values []string) []string {
	allRoles := []string{} // roles before removing duplicates
	for _, val := range values {
		// build our list of tags to look for matches with
		checkTags := map[string]string{}
		for k, v := range tags {
			checkTags[k] = v
		}

		// add this specific key/value pair
		checkTags[key] = val

		// add all the matches to our list
		allRoles = append(allRoles, r.GetMatchingRoles(checkTags)...)
	}
	// remove duplicates
	roles := []string{}
	dedup := map[string]bool{}
	for _, role := range allRoles {
		if _, ok := dedup[role]; !ok {
			roles = append(roles, role)
			dedup[role] = true
		}
	}
	return roles
}

// UsefulTags takes a map of tag key/value pairs and returns a list
// of tag keys which result in additional filtering
func (r *RoleTags) UsefulTags(tags map[string]string) []string {
	roles := r.GetMatchingRoles(tags)
	uniqueTags := map[string]map[string]int{}
	for _, role := range roles {
		for k, v := range (*r)[role] {
			if _, ok := uniqueTags[k]; !ok {
				uniqueTags[k] = map[string]int{}
				uniqueTags[k][v] = 1
			} else {
				uniqueTags[k][v] += 1
			}
		}
	}

	tagKeys := []string{}
	tagMatches := map[string]bool{}
	currentRoleCnt := len(roles)
	for k, tags := range uniqueTags {
		for _, cnt := range tags {
			if cnt < currentRoleCnt {
				if _, ok := tagMatches[k]; !ok {
					tagKeys = append(tagKeys, k)
					tagMatches[k] = true
				}
			}
		}
	}
	return tagKeys
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

package sso

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
	"sort"
)

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

	sort.Strings(roles)

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

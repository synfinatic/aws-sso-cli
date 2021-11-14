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
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
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
	for key := range *t {
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
	sort.Strings(keys)
	return keys
}

// reformatHistory modifies the History tag values to their human format for the selector
func reformatHistory(value string) string {
	x := strings.Split(value, ",")

	// oldformat
	if len(x) == 1 {
		return value
	}

	i, err := strconv.ParseInt(x[1], 10, 64)
	if err != nil {
		log.WithError(err).Fatalf("Unable to parse: %s", value)
	}

	d := time.Since(time.Unix(i, 0)).Truncate(time.Second)
	var s string

	if d.Hours() >= 1 {
		s = d.String()
	} else if d.Minutes() >= 1 {
		s = fmt.Sprintf("0h%s", d.String())
	} else {
		s = fmt.Sprintf("0h0m%s", d.String())
	}

	return fmt.Sprintf("[%s] %s", s, x[0])
}

// Returns a sorted unique list of tag values for the given key
func (t *TagsList) UniqueValues(key string) []string {
	x := *t

	if values, ok := x[key]; ok {
		sort.Strings(values)
		return values
	}

	return []string{}
}

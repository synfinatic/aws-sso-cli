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
	"strings"

	"github.com/c-bata/go-prompt"
	log "github.com/sirupsen/logrus"
)

type CompleterExec = func(*RunContext, *AWSSSO, string, string) error

type TagsCompleter struct {
	ctx      *RunContext
	sso      *SSOConfig
	awsSSO   *AWSSSO
	roleTags *RoleTags
	allTags  *TagsList
	suggest  []prompt.Suggest
	exec     CompleterExec
}

func NewTagsCompleter(ctx *RunContext, sso *SSOConfig, exec CompleterExec) *TagsCompleter {
	awssso := doAuth(ctx)
	roleTags := NewRoleTags(awssso, sso)
	allTags := NewTagsList()
	allTags.Merge(sso.GetAllTags())
	allTags.Merge(awssso.GetAllTags())

	return &TagsCompleter{
		ctx:      ctx,
		sso:      sso,
		awsSSO:   awssso,
		roleTags: roleTags,
		allTags:  allTags,
		suggest:  completeTags(roleTags, allTags, []string{}),
		exec:     exec,
	}
}

func (tc *TagsCompleter) Complete(d prompt.Document) []prompt.Suggest {
	if d.TextBeforeCursor() == "" {
		return prompt.FilterHasPrefix(tc.suggest, d.GetWordBeforeCursor(), true)
	}

	args := d.TextBeforeCursor()
	w := d.GetWordBeforeCursor()

	argsList := strings.Split(args, " ")
	suggest := completeTags(tc.roleTags, tc.allTags, argsList)
	//	return prompt.FilterHasPrefix(suggest, w, true)
	return prompt.FilterFuzzy(suggest, w, true)
}

func (tc *TagsCompleter) Executor(args string) {
	if args == "exit" {
		os.Exit(1)
	}
	argsMap := argsToMap(strings.Split(args, " "))

	ssoRoles := tc.roleTags.GetMatchingRoles(argsMap)
	if len(ssoRoles) == 0 {
		log.Fatalf("No matching roles")
	} else if len(ssoRoles) > 1 {
		log.Fatalf("Invalid selection")
	}

	accountid, role, err := getAccountRole(ssoRoles[0])
	if err != nil {
		log.Fatalf("Unable to exec: %s", err.Error())
	}
	err = tc.exec(tc.ctx, tc.awsSSO, accountid, role)
	if err != nil {
		log.Fatalf("Unable to exec: %s", err.Error())
	}
	return
}

// completeExitChecker impliments prompt.ExitChecker
func (tc *TagsCompleter) ExitChecker(in string, breakline bool) bool {
	return breakline // exit our Run() loop after user selects something
}

// return a list of suggestions based on user selected []key:value
func completeTags(roleTags *RoleTags, allTags *TagsList, args []string) []prompt.Suggest {
	suggestions := []prompt.Suggest{}

	currentTags := argsToMap(args)
	if roleTags.GetMatchCount(currentTags) == 1 {
		return suggestions // empty list if we have a single role
	}

	// roles which match the current tags
	currentRoles := roleTags.GetMatchingRoles(currentTags)
	currentCount := len(currentRoles)
	log.Debugf("currentRoles: %v", currentRoles)

	uniqueSuggestions := map[string]int{}

	// iterate through all our other tag types...
	for k, list := range *allTags {
		if list == nil {
			continue // skip empty
		}
		if _, ok := currentTags[k]; ok {
			continue // skip the tag type we've already selected
		}

		// scan our tag value choices
		for _, v := range list {
			// copy currentTags to selectedTags
			selectedTags := map[string]string{}
			for k, v := range currentTags {
				selectedTags[k] = v
			}

			// add this new tag/value
			selectedTags[k] = v
			log.Debugf("selectedTags: %v", selectedTags)

			// see if any roles match
			newRoles := roleTags.GetMatchingRoles(selectedTags)
			log.Debugf("newRoles: %v", newRoles)
			roleCount := len(newRoles)

			// if we have any roles, our suggestions
			if roleCount > 0 && roleCount < currentCount {
				arg := fmt.Sprintf("%s:%s", k, v)
				var descr string
				if roleCount > 1 {
					descr = fmt.Sprintf("%d roles", roleCount)
				} else {
					descr = newRoles[0] // fmt.Sprintf("Select: %s", newRoles[0])
				}
				if _, ok := uniqueSuggestions[arg]; !ok {
					uniqueSuggestions[arg] = 1
					suggestions = append(suggestions, prompt.Suggest{
						Text:        arg,
						Description: descr,
					})
				}
			}
		}
	}
	return suggestions
}

// Converts a list of key:value strings to a map
func argsToMap(args []string) map[string]string {
	tags := map[string]string{}
	for _, arg := range args {
		kv := strings.Split(arg, ":")
		if len(kv) > 2 {
			key := kv[0]
			tags[key] = strings.Join(kv[1:], ":")
		} else if len(kv) == 2 {
			tags[kv[0]] = kv[1]
		} // may have empty values
	}
	return tags
}

// Converts SSORoles to RoleInfo map
func SSORolesToRoleInfo(sroles []*SSORole) map[string][]RoleInfo {
	roles := map[string][]RoleInfo{}
	for _, r := range sroles {
		accountId := r.GetAccountId()
		_, ok := roles[accountId]
		if !ok {
			roles[accountId] = []RoleInfo{}
		}
		// this is a pretty limited set of fields
		roles[accountId] = append(roles[accountId], RoleInfo{
			RoleName:    r.GetRoleName(),
			AccountId:   accountId,
			AccountName: r.Account.Name,
			Profile:     r.Profile,
		})
	}

	return roles
}

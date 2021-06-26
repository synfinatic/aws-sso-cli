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
	"strings"

	"github.com/c-bata/go-prompt"
	log "github.com/sirupsen/logrus"
)

type TagsCompleter struct {
	ctx     *RunContext
	sso     *SSOConfig
	suggest []prompt.Suggest
}

func NewTagsCompleter(ctx *RunContext, sso *SSOConfig) *TagsCompleter {
	return &TagsCompleter{
		ctx:     ctx,
		sso:     sso,
		suggest: completeTags(sso, []string{}),
	}
}

func (tc *TagsCompleter) Complete(d prompt.Document) []prompt.Suggest {
	if d.TextBeforeCursor() == "" {
		return prompt.FilterHasPrefix(tc.suggest, d.GetWordBeforeCursor(), true)
	}

	args := d.TextBeforeCursor()
	w := d.GetWordBeforeCursor()

	argsList := strings.Split(args, " ")
	suggest := completeTags(tc.sso, argsList)
	//	return prompt.FilterHasPrefix(suggest, w, true)
	return prompt.FilterFuzzy(suggest, w, true)
}

func (tc *TagsCompleter) Executor(args string) {
	argsMap := argsToTags(strings.Split(args, " "))

	allRoles := map[string][]RoleInfo{}
	err := tc.ctx.Store.GetRoles(&allRoles)
	ssoRoles := tc.sso.GetRoleMatches(argsMap)

	accountid := ssoRoles[0].GetAccountId()
	role := ssoRoles[0].GetRoleName()
	awssso := doAuth(tc.ctx)
	err = execCmd(tc.ctx, awssso, accountid, role)
	if err != nil {
		log.Fatalf("Unable to exec: %s", err.Error())
	}
	return
}

// completeExitChecker impliments prompt.ExitChecker
func (tc *TagsCompleter) ExitChecker(in string, breakline bool) bool {
	return breakline // exit our Run() loop after user selects something
}

func completeTags(sso *SSOConfig, args []string) []prompt.Suggest {
	suggestions := []prompt.Suggest{}

	currentTags := argsToTags(args)
	currentRoles := sso.GetRoleMatches(currentTags)

	allTags := sso.GetAllTags()
	for k, list := range allTags {
		for _, v := range list {
			// don't include tag keys we already have selected
			if len(currentTags) > 0 {
				if _, ok := currentTags[k]; ok {
					continue
				}
			}

			arg := fmt.Sprintf("%s:%s", k, v)
			theseArgs := append(args, arg)
			tags := argsToTags(theseArgs)
			newRoles := sso.GetRoleMatches(tags)
			roleCount := len(newRoles)
			if roleCount > 0 && !rolesMatch(currentRoles, newRoles) {
				var descr string
				if roleCount > 1 {
					descr = fmt.Sprintf("%d roles", roleCount)
				} else {
					descr = "Select Role"
				}
				suggestions = append(suggestions, prompt.Suggest{
					Text:        arg,
					Description: descr,
				})
			}
		}
	}
	return suggestions
}

func argsToTags(args []string) map[string]string {
	tags := map[string]string{}
	for _, arg := range args {
		kv := strings.Split(arg, ":")
		if len(kv) >= 2 {
			key := kv[0]
			tags[key] = strings.Join(kv[1:], ":")
		}
	}
	return tags
}

func mapHasAlready(m map[string]string, k, v string) bool {
	mv, ok := m[k]
	if !ok || mv != v {
		return false
	}
	return false
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

// rolesMatch returns if the two slices contain the same roles
func rolesMatch(a, b []*SSORole) bool {
	if len(a) != len(b) {
		return false
	}

	for _, role := range a {
		match := false
		for _, check := range b {
			if role.ARN == check.ARN {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	return true
}

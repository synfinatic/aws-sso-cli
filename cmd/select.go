package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2022 Aaron Turner  <synfinatic at gmail dot com>
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
	"regexp"
	"strings"

	"github.com/c-bata/go-prompt"
	//	"github.com/davecgh/go-spew/spew"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
	"github.com/synfinatic/aws-sso-cli/sso"
)

type CompleterExec = func(*RunContext, *sso.AWSSSO, int64, string) error

type TagsCompleter struct {
	ctx      *RunContext
	sso      *sso.SSOConfig
	roleTags *sso.RoleTags
	allTags  *sso.TagsList
	suggest  []prompt.Suggest
	exec     CompleterExec
}

func NewTagsCompleter(ctx *RunContext, s *sso.SSOConfig, exec CompleterExec) *TagsCompleter {
	set := ctx.Settings
	roleTags := set.Cache.GetRoleTagsSelect()
	allTags := set.Cache.GetAllTagsSelect()

	return &TagsCompleter{
		ctx:      ctx,
		sso:      s,
		roleTags: roleTags,
		allTags:  allTags,
		suggest:  completeTags(roleTags, allTags, set.AccountPrimaryTag, []string{}),
		exec:     exec,
	}
}

var CompleteSpaceReplace *regexp.Regexp = regexp.MustCompile(`\s+`)

func (tc *TagsCompleter) Complete(d prompt.Document) []prompt.Suggest {
	if d.TextBeforeCursor() == "" {
		return prompt.FilterHasPrefix(tc.suggest, d.GetWordBeforeCursor(), true)
	}

	args := d.TextBeforeCursor()
	w := d.GetWordBeforeCursor()

	// remove any extra spaces
	cleanArgs := CompleteSpaceReplace.ReplaceAllString(args, " ")
	argsList := strings.Split(cleanArgs, " ")
	suggest := completeTags(tc.roleTags, tc.allTags, tc.ctx.Settings.AccountPrimaryTag, argsList)
	return prompt.FilterHasPrefix(suggest, w, true)
}

// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html
var isRoleARN *regexp.Regexp = regexp.MustCompile(`^arn:aws:iam::\d+:role/[a-zA-Z0-9\+=,\.@_-]+$`)
var NoSpaceAtEnd *regexp.Regexp = regexp.MustCompile(`\s+$`)

func (tc *TagsCompleter) Executor(args string) {
	args = NoSpaceAtEnd.ReplaceAllString(args, "")
	if args == "exit" {
		os.Exit(1)
	}

	var roleArn string
	argsList := strings.Split(args, " ")
	if isRoleARN.MatchString(argsList[len(argsList)-1]) {
		// last word is our ARN, no need to filter
		roleArn = argsList[len(argsList)-1]
	} else {
		// Use the filter map
		argsMap, _, _ := argsToMap(strings.Split(args, " "))

		ssoRoles := tc.roleTags.GetMatchingRoles(argsMap)
		if len(ssoRoles) == 0 {
			log.Fatalf("Invalid selection: No matching roles.")
		} else if len(ssoRoles) > 1 {
			log.Fatalf("Invalid selection: Too many roles match selected values.")
		}
		roleArn = ssoRoles[0]
	}

	aId, rName, err := utils.ParseRoleARN(roleArn)
	if err != nil {
		log.Fatalf("Unable to parse %s: %s", roleArn, err.Error())
	}
	awsSSO := doAuth(tc.ctx)
	err = tc.exec(tc.ctx, awsSSO, aId, rName)
	if err != nil {
		log.Fatalf("Unable to exec: %s", err.Error())
	}
}

// completeExitChecker implements prompt.ExitChecker
func (tc *TagsCompleter) ExitChecker(in string, breakline bool) bool {
	return breakline // exit our Run() loop after user selects something
}

// return a list of suggestions based on user selected []key:value
func completeTags(roleTags *sso.RoleTags, allTags *sso.TagsList, accountPrimaryTags []string, args []string) []prompt.Suggest {
	suggestions := []prompt.Suggest{}

	currentTags, nextKey, nextValue := argsToMap(args)
	if roleTags.GetMatchCount(currentTags) == 1 {
		return suggestions // empty list if we have a single role
	}

	if nextKey == "" {
		// Find roles which match selection & remaining Tag keys
		currentRoles := roleTags.GetMatchingRoles(currentTags)

		selectedKeys := []string{}
		for k := range currentTags {
			selectedKeys = append(selectedKeys, k)
		}

		returnedRoles := map[string]bool{}

		for _, key := range allTags.UniqueKeys(selectedKeys) {
			uniqueRoles := roleTags.GetPossibleUniqueRoles(currentTags, key, (*allTags)[key])
			if len(args) > 0 && len(uniqueRoles) == len(currentRoles) {
				// skip keys which can't reduce our options
				for _, role := range uniqueRoles {
					if _, ok := returnedRoles[role]; ok {
						// don't return the same role multiple times
						continue
					}

					var description string
					for _, tag := range accountPrimaryTags {
						// don't re-use a tag that was alraedy specified by the user
						for _, v := range args {
							if v == tag {
								continue
							}
						}
						if val, ok := roleTags.GetRoleTags(role)[tag]; ok {
							if val == "" { // ignore empty values
								continue
							}
							description = fmt.Sprintf("%s:%s", tag, val)
							break
						}
					}
					suggestions = append(suggestions, prompt.Suggest{
						Text:        role,
						Description: description,
					})
					returnedRoles[role] = true
				}
				continue
			}
			if len(uniqueRoles) > 0 {
				suggestions = append(suggestions, prompt.Suggest{
					Text: key,
					Description: fmt.Sprintf("%d roles/%d choices", len(uniqueRoles),
						len(allTags.UniqueValues(key))),
				})
			}
		}
	} else if nextValue == "" {
		// We have a 'nextKey', so search for Tag values which match
		values := (*allTags).UniqueValues(nextKey)
		if len(values) > 0 {
			// found exact match for our nextKey
			for _, value := range values {
				checkArgs := []string{}
				for _, v := range args {
					if v != "" { // don't include the empty
						checkArgs = append(checkArgs, v)
					}
				}
				checkArgs = append(checkArgs, value)
				checkArgs = append(checkArgs, "") // mark value as "complete"
				argsMap, _, _ := argsToMap(checkArgs)
				checkRoles := roleTags.GetMatchingRoles(argsMap)
				roleCnt := len(checkRoles)
				desc := ""
				switch roleCnt {
				case 0:
					continue

				case 1:
					desc = checkRoles[0] // the ARN of the role we selected

				default:
					desc = fmt.Sprintf("%d roles", roleCnt)
				}
				suggestions = append(suggestions, prompt.Suggest{
					Text:        value,
					Description: desc,
				})
			}
		} else {
			// no exact match, look for the key

			usedKeys := []string{}
			for k := range currentTags {
				usedKeys = append(usedKeys, k)
			}
			remainKeys := allTags.UniqueKeys(usedKeys)

			for _, checkKey := range remainKeys {
				if strings.Contains(strings.ToLower(checkKey), strings.ToLower(nextKey)) {
					suggestions = append(suggestions, prompt.Suggest{
						Text:        checkKey,
						Description: fmt.Sprintf("%d choices", len(allTags.UniqueValues(checkKey))),
					})
				}
			}
		}
	} else {
		// We have a 'nextValue', so search for Tag values which match
		for _, checkValue := range allTags.UniqueValues(nextKey) {
			if strings.Contains(strings.ToLower(checkValue), strings.ToLower(nextValue)) {
				testSet := map[string]string{}
				for k, v := range currentTags {
					testSet[k] = v
				}
				testSet[nextKey] = checkValue
				matchedRoles := roleTags.GetMatchingRoles(testSet)
				matchedCnt := len(matchedRoles)
				if matchedCnt > 0 {
					suggestions = append(suggestions, prompt.Suggest{
						Text:        checkValue,
						Description: fmt.Sprintf("%d roles", matchedCnt),
					})
				}
			}
		}
	}
	return suggestions
}

// Converts a list of 'key value' strings to a key/value map and uncompleted key/value pair
func argsToMap(args []string) (map[string]string, string, string) {
	tags := map[string]string{}
	retKey := ""
	retValue := ""
	cleanArgs := []string{}
	completeWord := false

	// remove any empty strings
	for _, a := range args {
		if a != "" {
			cleanArgs = append(cleanArgs, a)
		}
	}

	if len(cleanArgs) == 0 {
		return map[string]string{}, "", ""
	} else if len(cleanArgs) == 1 {
		return map[string]string{}, cleanArgs[0], ""
	}

	// our last word is complete
	if args[len(args)-1] == "" {
		completeWord = true
	}

	if len(cleanArgs)%2 == 0 && completeWord {
		// we have a complete set of key => value pairs
		for i := 0; i < len(args)-1; i += 2 {
			tags[cleanArgs[i]] = cleanArgs[i+1]
		}
	} else if len(cleanArgs)%2 == 0 {
		// final word is an incomplete value
		for i := 0; i <= len(cleanArgs)-2; i += 2 {
			tags[cleanArgs[i]] = cleanArgs[i+1]
		}
		retKey = cleanArgs[len(cleanArgs)-2]
		retValue = cleanArgs[len(cleanArgs)-1]
	} else {
		// final word is a (part of a) key
		retKey = cleanArgs[len(cleanArgs)-1]
		cleanArgs = cleanArgs[:len(cleanArgs)-1]
		for i := 0; i < len(cleanArgs)-2; i += 2 {
			tags[cleanArgs[i]] = cleanArgs[i+1]
		}
	}
	return tags, retKey, retValue
}

package cache

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
	"strconv"
	"strings"
	"time"

	"github.com/synfinatic/aws-sso-cli/internal/awsparse"
)

// AddHistory adds a role ARN to the History list up to the max number of entries
// and then removes the History tag from any roles that aren't in our list
func (c *Cache) AddHistory(s SettingsReader, item string) {
	// If it's already in the list, remove item
	c.deleteHistoryItem(item)

	c.GetSSO().History = append([]string{item}, c.GetSSO().History...) // push on top
	for int64(len(c.GetSSO().History)) > s.GetHistoryLimit() {
		// remove the oldest entry
		c.GetSSO().History = c.GetSSO().History[:len(c.GetSSO().History)-1]
	}

	// Update our Tags for this new item
	aId, roleName, _ := awsparse.ParseRoleARN(item)
	if a, ok := c.GetSSO().Roles.Accounts[aId]; ok {
		if r, ok := a.Roles[roleName]; ok {
			r.Tags["History"] = fmt.Sprintf("%s:%s,%d", a.Alias, roleName, time.Now().Unix())
		}
	}

	// remove any history tags not in our list
	roles := c.GetSSO().Roles.MatchingRolesWithTagKey("History")

	for _, role := range roles {
		exists := false
		for _, history := range c.GetSSO().History {
			if history == (*role).Arn {
				exists = true
				break
			}
		}

		// remove any History tag for roles which don't exist in c.GetSSO().History
		if !exists {
			aId, roleName, _ := awsparse.ParseRoleARN(role.Arn)
			delete(c.GetSSO().Roles.Accounts[aId].Roles[roleName].Tags, "History")
		}
	}
}

func (c *Cache) deleteHistoryItem(arn string) {
	for i, value := range c.GetSSO().History {
		if arn == value {
			c.GetSSO().History = append(c.GetSSO().History[:i], c.GetSSO().History[i+1:]...)
			break
		}
	}
}

// deleteOldHistory removes any items from history which are older than HistoryMinutes.
// Does not save to disk; only updates the in-memory cache.
func (c *Cache) deleteOldHistory(s SettingsReader) {
	if s.GetHistoryMinutes() <= 0 {
		// no op if HistoryMinutes <= 0
		return
	}

	cache := c.GetSSO()

	newHistoryItems := []string{}

	// iterate over each ARN in our History list
	for _, arn := range cache.History {
		id, role, err := awsparse.ParseRoleARN(arn)
		if err != nil {
			log.Debug("Unable to parse History ARN", "arn", arn, "error", err.Error())
			c.deleteHistoryItem(arn)
			continue
		}

		// for the given ARN, lookup the History tag
		if a, ok := cache.Roles.Accounts[id]; ok {
			if r, ok := a.Roles[role]; ok {
				// figure out if this history item has expired
				history, ok := r.Tags["History"]
				if !ok || history == "" {
					// doesn't have anything to expire
					log.Debug("ARN in history list without a History tag in cache?", "arn", arn)
					c.deleteHistoryItem(arn)
					continue
				}

				values := strings.SplitN(history, ",", 2)
				if len(values) != 2 {
					log.Debug("Too few fields for History Tag", "arn", r.Arn, "history", history)
					c.deleteHistoryItem(arn)
					continue
				}
				lastTime, err := strconv.ParseInt(values[1], 10, 64)
				if err != nil {
					log.Debug("Unable to parse History Tag", "arn", r.Arn, "history", history, "error", err.Error())
					c.deleteHistoryItem(arn)
					continue
				}

				d := time.Since(time.Unix(lastTime, 0))
				if int64(d.Minutes()) < s.GetHistoryMinutes() {
					// keep current entries in our list
					newHistoryItems = append(newHistoryItems, arn)
				} else {
					// else, delete the tag and remove the item from History by
					// not appending it to newHistoryItems
					delete(r.Tags, "History")
					c.deleteHistoryItem(arn)
					log.Debug("Removed expired history role", "arn", r.Arn)
				}
			} else {
				c.deleteHistoryItem(arn)
				log.Debug("History contains but no role by that name", "arn", arn)
			}
		} else {
			c.deleteHistoryItem(arn)
			log.Debug("History contains but no account by that name", "arn", arn)
		}
	}

	c.GetSSO().History = newHistoryItems
}

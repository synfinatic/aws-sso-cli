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
	"strings"

	"github.com/synfinatic/aws-sso-cli/internal/awsparse"
	"github.com/synfinatic/aws-sso-cli/internal/tags"
)

// SetRoleExpires updates the Expires time in the cache.  expires is Unix epoch time in sec
func (c *Cache) SetRoleExpires(arn string, expires int64) error {
	flat, err := c.GetRole(arn)
	if err != nil {
		return err
	}

	cache := c.GetSSO()
	cache.Roles.Accounts[flat.AccountId].Roles[flat.RoleName].Expires = expires
	return c.Save(false)
}

// MarkRolesExpired marks all IAM role credentials in the cache as expired
func (c *Cache) MarkRolesExpired() error {
	cache := c.GetSSO()
	for accountId := range cache.Roles.Accounts {
		for _, role := range cache.Roles.Accounts[accountId].Roles {
			(*role).Expires = 0
		}
	}
	return c.Save(false)
}

// GetAllTagsSelect returns all tags, but with spaces replaced with underscores
func (c *Cache) GetAllTagsSelect() *tags.TagsList {
	cache := c.GetSSO()
	t := cache.Roles.GetAllTags()
	fixedTags := tags.NewTagsList()
	for k, values := range *t {
		key := strings.ReplaceAll(k, " ", "_")
		for _, v := range values {
			if key == "History" {
				v = tags.ReformatHistory(v)
			}
			fixedTags.Add(key, strings.ReplaceAll(v, " ", "_"))
		}
	}
	return fixedTags
}

// GetRoleTagsSelect returns all the tags for each role with all the spaces
// replaced with underscores
func (c *Cache) GetRoleTagsSelect() *RoleTags {
	ret := RoleTags{}
	cache := c.GetSSO()
	fList := cache.Roles.GetAllRoles()
	for _, role := range fList {
		ret[role.Arn] = map[string]string{}
		for k, v := range role.Tags {
			key := strings.ReplaceAll(k, " ", "_")
			if key == "History" {
				v = tags.ReformatHistory(v)
			}
			value := strings.ReplaceAll(v, " ", "_")
			ret[role.Arn][key] = value
		}
	}
	return &ret
}

// GetRole returns the AWSRoleFlat for the given role ARN
func (c *Cache) GetRole(arn string) (*AWSRoleFlat, error) {
	accountId, roleName, err := awsparse.ParseRoleARN(arn)
	if err != nil {
		return &AWSRoleFlat{}, err
	}
	cache := c.GetSSO()
	return cache.Roles.GetRole(accountId, roleName)
}

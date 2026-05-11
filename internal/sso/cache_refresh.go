package sso

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
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/synfinatic/aws-sso-cli/internal/awsparse"
)

const (
	SLOW_FETCH_SECONDS = 2 // number of seconds before notifying users
)

// Refresh updates our cached Roles based on AWS SSO & our Config
// but does not save this data!  Returns the number of roles added/deleted
func (c *Cache) Refresh(sso *AWSSSO, config *SSOConfig, ssoName string, threads int) (int, int, error) {
	// Only refresh once per execution
	if c.refreshed {
		return 0, 0, nil
	}
	c.refreshed = true
	log.Debug("refreshing SSO cache", "SSOname", ssoName)

	// save role creds expires time
	expires := map[string]int64{}
	cache := c.GetSSO()
	now := time.Now().Unix()
	for _, account := range cache.Roles.Accounts {
		for _, role := range account.Roles {
			if role.Expires > now {
				expires[role.Arn] = role.Expires
			}
		}
	}

	// save existing History tags
	historyTags := map[string]string{}
	for _, arn := range c.SSO[ssoName].History {
		roleFlat, err := c.GetRole(arn)
		if err != nil {
			continue
		}
		if value, ok := roleFlat.Tags["History"]; ok {
			historyTags[arn] = value
		}
	}

	// zero out our current roles cache entries so they don't get merged
	oldRoles := cache.Roles.GetAllRoles()
	oldRoleArns := []string{}
	for _, role := range oldRoles {
		oldRoleArns = append(oldRoleArns, role.Arn)
	}

	c.SSO[ssoName].Roles = &Roles{}
	c.SSO[ssoName].ConfigHash = config.GetConfigHash(c.settings.ProfileFormat)

	// load our AWSSSO & Config
	r, err := c.NewRoles(sso, config, threads)
	if err != nil {
		return 0, 0, err
	}
	c.SSO[ssoName].Roles = r

	// figure out what roles were added/deleted
	newRoles := c.SSO[ssoName].Roles.GetAllRoles()
	newRoleArns := []string{}
	for _, role := range newRoles {
		newRoleArns = append(newRoleArns, role.Arn)
	}

	// do we have any new or deleted roles?
	added, deleted := 0, 0
	for _, arn := range newRoleArns {
		if !slices.Contains(oldRoleArns, arn) {
			added++
		}
	}
	for _, arn := range oldRoleArns {
		if !slices.Contains(newRoleArns, arn) {
			deleted++
		}
	}

	// restore any configured roles that are not in AWS SSO
	for aId, account := range config.Accounts {
		accountId, err := awsparse.AccountIdToInt64(aId)
		if err != nil {
			return 0, 0, fmt.Errorf("unable to parse accountId from config.yaml %s: %s", aId, err.Error())
		}
		// if aId is scientific notation, convert to int64 string
		aId, _ := awsparse.AccountIdToString(accountId)
		for rName, role := range account.Roles {
			if role.Via != "" {
				log.Info("restoring via role", "role", rName, "account", accountId)
				if _, ok := cache.Roles.Accounts[accountId]; !ok {
					c.SSO[ssoName].Roles.Accounts[accountId] = &AWSAccount{
						Roles: map[string]*AWSRole{},
						Tags:  map[string]string{},
					}
				}
				if role.Tags == nil {
					role.Tags = map[string]string{
						"AccountAlias": c.SSO[ssoName].Roles.Accounts[accountId].Alias,
						"AccountID":    aId,
						"Email":        c.SSO[ssoName].Roles.Accounts[accountId].EmailAddress,
						"Role":         rName,
					}
				}
				c.SSO[ssoName].Roles.Accounts[accountId].Roles[rName] = &AWSRole{
					Arn:           role.ARN,
					DefaultRegion: role.DefaultRegion,
					Profile:       role.Profile,
					Tags:          role.Tags,
					Via:           role.Via,
				}
			}
		}
	}

	// restore our history tags & expires
	for _, account := range c.SSO[ssoName].Roles.Accounts {
		for _, role := range account.Roles {
			if value, ok := historyTags[role.Arn]; ok {
				role.Tags["History"] = value
			}
			if value, ok := expires[role.Arn]; ok {
				role.Expires = value
			}
		}
	}
	c.ConfigCreatedAt = config.CreatedAt()
	return added, deleted, nil
}

// NewRoles merges data from AWS SSO and the config file into a fresh Roles struct.
func (c *Cache) NewRoles(as *AWSSSO, config *SSOConfig, threads int) (*Roles, error) {
	r := Roles{
		SSORegion:     config.SSORegion,
		StartUrl:      config.StartUrl,
		DefaultRegion: config.DefaultRegion,
		Accounts:      map[int64]*AWSAccount{},
		SSOName:       config.settings.DefaultSSO,
	}

	if err := c.addSSORoles(&r, as, threads); err != nil {
		return &Roles{}, err
	}

	if err := c.addConfigRoles(&r, config); err != nil {
		return &Roles{}, err
	}

	if err := r.CheckProfiles(c.settings); err != nil {
		return &Roles{}, err
	}

	return &r, nil
}

// fetchSSORole is a goroutine worker that fetches RoleInfo for each AccountInfo received.
func fetchSSORole(id int, as *AWSSSO, aInfo <-chan AccountInfo, rInfo chan<- []RoleInfo) {
	for {
		a := <-aInfo
		if a.AccountId == "" {
			// need some way to exit our worker...
			break
		}
		log.Debug("Worker processing", "worker", id, "accountID", a.AccountId)
		roles, err := as.GetRoles(a)
		if err != nil {
			panic(fmt.Sprintf("Unable to get AWS SSO roles: %s", err.Error()))
		}
		rInfo <- roles
	}
}

// processSSORoles updates r with the list of RoleInfo using the SSOCache for
// preserving existing Expires and History tag values.
func processSSORoles(roles []RoleInfo, cache *SSOCache, r *Roles) {
	for _, role := range roles {
		log.Debug(fmt.Sprintf("Processing %s:%s", role.AccountId, role.RoleName))
		accountId := role.GetAccountId64()

		if _, ok := r.Accounts[accountId]; !ok {
			r.Accounts[accountId] = &AWSAccount{
				Alias:        role.AccountName, // AWS SSO calls it `AccountName`
				EmailAddress: role.EmailAddress,
				Tags:         map[string]string{},
				Roles:        map[string]*AWSRole{},
			}
		}

		r.Accounts[accountId].Roles[role.RoleName] = &AWSRole{
			Arn: awsparse.MakeRoleARN(accountId, role.RoleName),
			Tags: map[string]string{
				"AccountID":    role.AccountId,
				"AccountAlias": role.AccountName, // AWS SSO calls it `AccountName`
				"Email":        role.EmailAddress,
				"Role":         role.RoleName,
			},
		}
		// need to copy over the Expires & History fields from our current cache
		if _, ok := cache.Roles.Accounts[accountId]; ok {
			if _, ok := cache.Roles.Accounts[accountId].Roles[role.RoleName]; ok {
				if expires := cache.Roles.Accounts[accountId].Roles[role.RoleName].Expires; expires > 0 {
					r.Accounts[accountId].Roles[role.RoleName].Expires = expires
				}
				if v, ok := cache.Roles.Accounts[accountId].Roles[role.RoleName].Tags["History"]; ok {
					r.Accounts[accountId].Roles[role.RoleName].Tags["History"] = v
				}
			}
		}
	}
}

// addSSORoles retrieves all SSO roles from AWS SSO and places them in r.
// The first account is fetched serially to allow token refresh; remaining
// accounts are fetched in parallel via a bounded worker pool.
func (c *Cache) addSSORoles(r *Roles, as *AWSSSO, threads int) error {
	cache := c.GetSSO()

	accounts, err := as.GetAccounts()
	if err != nil {
		return fmt.Errorf("unable to get list of AWS accounts via AWS SSO: %s", err.Error())
	}

	if len(accounts) == 0 {
		return fmt.Errorf("no AWS accounts found in AWS SSO")
	}

	// Our first query must NOT be part of the worker pool so our AccessToken
	// can be updated
	firstJob, accounts := accounts[0], accounts[1:]
	roles, err := as.GetRoles(firstJob)
	if err != nil {
		return err
	}
	processSSORoles(roles, cache, r)

	// Per #448, doing this serially is too slow for many accounts.  Hence,
	// we'll use a worker pool.
	if len(accounts) > 0 {
		workers := c.settings.Threads
		if threads > 0 {
			workers = threads
		}
		if workers > len(accounts) {
			workers = len(accounts)
		}

		tasks := make(chan AccountInfo, len(accounts))
		results := make(chan []RoleInfo, len(accounts))

		// feed our workers with our other accounts
		for _, aInfo := range accounts {
			tasks <- aInfo
		}
		close(tasks)

		// start our workers...
		for w := 1; w <= workers; w++ {
			go fetchSSORole(w, as, tasks, results)
		}

		// Notify
		ticker := time.NewTicker(SLOW_FETCH_SECONDS * time.Second)
		defer ticker.Stop()

		for count := 0; count < len(accounts); {
			select {
			case roles := <-results:
				processSSORoles(roles, cache, r)
				count++ // increment count only when processing results
				log.Debug("processed", "accounts", count, "new_roles", len(roles), "total_roles", len(r.GetAllRoles()))
			case <-ticker.C:
				log.Warn(fmt.Sprintf("fetching roles for %d accounts, this might take a while...", len(accounts)+1))
				ticker.Stop() // one-time warning; stop to avoid repeated fires
			}
		}
		close(results)
	}
	return nil
}

type contextKey string

const (
	accountIdKey contextKey = "accountID"
)

// addConfigRoles decorates the provided Roles with the contents of our config file.
// For accounts and roles not in SSO, entries may also be created here.
func (c *Cache) addConfigRoles(r *Roles, config *SSOConfig) error {
	for accountId, account := range config.Accounts {
		id, err := awsparse.AccountIdToInt64(accountId)
		if err != nil {
			return err
		}
		ctx := context.WithValue(context.Background(), accountIdKey, id)
		if _, ok := r.Accounts[id]; !ok {
			log.DebugContext(ctx, "config.yaml defines an AWS AccountID, but you don't have access.")
			continue
		}
		r.Accounts[id].DefaultRegion = account.DefaultRegion
		r.Accounts[id].Name = account.Name

		// set our account tags
		for k, v := range config.Accounts[accountId].Tags {
			r.Accounts[id].Tags[k] = v
		}

		// set the AWS SSO tags for all the SSO roles
		for roleName := range r.Accounts[id].Roles {
			aId, _ := awsparse.AccountIdToString(id)
			r.Accounts[id].Roles[roleName].Tags["AccountID"] = aId
			r.Accounts[id].Roles[roleName].Tags["AccountAlias"] = r.Accounts[id].Alias
			r.Accounts[id].Roles[roleName].Tags["Email"] = r.Accounts[id].EmailAddress
			r.Accounts[id].Roles[roleName].Tags["Role"] = roleName
			if r.Accounts[id].Name != "" {
				r.Accounts[id].Roles[roleName].Tags["AccountName"] = r.Accounts[id].Name
			}
			if r.Accounts[id].Roles[roleName].DefaultRegion != "" {
				r.Accounts[id].Roles[roleName].Tags["DefaultRegion"] = r.Accounts[id].Roles[roleName].DefaultRegion
			}
		}

		// set the tags from the config file
		for roleName, role := range config.Accounts[accountId].Roles {
			if _, ok := r.Accounts[id].Roles[roleName]; !ok {
				log.DebugContext(ctx, "config.yaml defines a role but you don't have access", "role", roleName)
				continue
			}
			r.Accounts[id].Roles[roleName].Arn = awsparse.MakeRoleARN(id, roleName)
			r.Accounts[id].Roles[roleName].Profile = role.Profile
			r.Accounts[id].Roles[roleName].DefaultRegion = r.Accounts[id].DefaultRegion
			r.Accounts[id].Roles[roleName].Via = role.Via
			if role.DefaultRegion != "" {
				r.Accounts[id].Roles[roleName].DefaultRegion = role.DefaultRegion
			}
			// Copy the account tags to the role
			for k, v := range config.Accounts[accountId].Tags {
				r.Accounts[id].Roles[roleName].Tags[k] = v
			}
			// Insert role specific tags (possible overwrite of account level)
			for k, v := range role.Tags {
				r.Accounts[id].Roles[roleName].Tags[k] = v
			}
		}
	}
	return nil
}

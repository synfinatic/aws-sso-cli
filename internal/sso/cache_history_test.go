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
	"fmt"
	"log/slog"
	"time"

	"github.com/stretchr/testify/assert"
	testlogger "github.com/synfinatic/flexlog/test"
)

func (suite *CacheTestSuite) TestAddHistory() {
	t := suite.T()

	c := &Cache{
		settings: &Settings{
			HistoryLimit:   1,
			HistoryMinutes: 90,
		},
		ssoName: "Default",
		SSO: map[string]*SSOCache{
			"Default": {
				name:       "Default",
				LastUpdate: 2345,
				History:    []string{},
				Roles: &Roles{
					Accounts: map[int64]*AWSAccount{
						123456789012: {
							Alias: "MyAccount",
							Roles: map[string]*AWSRole{
								"Foo": {
									Arn: "arn:aws:iam::123456789012:role/Foo",
									Tags: map[string]string{
										"AccountAlias": "MyAccount",
										"RoleName":     "Foo",
									},
								},
								"Bar": {
									Arn: "arn:aws:iam::123456789012:role/Bar",
									Tags: map[string]string{
										"AccountAlias": "MyAccount",
										"RoleName":     "Bar",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	cache := c.GetSSO()
	assert.Equal(t, []string{}, cache.History)

	now := time.Now().Unix()

	// Basic add
	c.AddHistory("arn:aws:iam::123456789012:role/Foo")
	assert.Equal(t, []string{"arn:aws:iam::123456789012:role/Foo"}, cache.History)
	tag := fmt.Sprintf("MyAccount:Foo,%d", now)
	assert.Equal(t, tag, c.GetSSO().Roles.Accounts[123456789012].Roles["Foo"].Tags["History"])

	// Add again which should be a no-op
	c.AddHistory("arn:aws:iam::123456789012:role/Foo")
	assert.Equal(t, []string{"arn:aws:iam::123456789012:role/Foo"}, cache.History)
	tag = fmt.Sprintf("MyAccount:Foo,%d", now)
	assert.Equal(t, tag, c.GetSSO().Roles.Accounts[123456789012].Roles["Foo"].Tags["History"])

	// Add a new item which expires the previous item
	c.AddHistory("arn:aws:iam::123456789012:role/Bar")
	assert.Equal(t, []string{"arn:aws:iam::123456789012:role/Bar"}, cache.History)
	tag = fmt.Sprintf("MyAccount:Bar,%d", now)
	assert.NotContains(t, "History", c.GetSSO().Roles.Accounts[123456789012].Roles["Foo"].Tags)
	assert.Equal(t, tag, c.GetSSO().Roles.Accounts[123456789012].Roles["Bar"].Tags["History"])

	// Add the same item again
	c.AddHistory("arn:aws:iam::123456789012:role/Bar")
	assert.Equal(t, []string{"arn:aws:iam::123456789012:role/Bar"}, cache.History)

	// Basic tests with two items in the History slice
	c.settings.HistoryLimit = 2
	c.AddHistory("arn:aws:iam::123456789012:role/Foo")
	assert.Equal(t, []string{
		"arn:aws:iam::123456789012:role/Foo",
		"arn:aws:iam::123456789012:role/Bar"}, cache.History)

	// this should be a no-op
	c.AddHistory("arn:aws:iam::123456789012:role/Foo")
	assert.Equal(t, []string{
		"arn:aws:iam::123456789012:role/Foo",
		"arn:aws:iam::123456789012:role/Bar"}, cache.History)

	// reorder args
	c.AddHistory("arn:aws:iam::123456789012:role/Baz")
	assert.Equal(t, []string{
		"arn:aws:iam::123456789012:role/Baz",
		"arn:aws:iam::123456789012:role/Foo"}, cache.History)

	c.AddHistory("arn:aws:iam::123456789012:role/Foo")
	assert.Equal(t, []string{
		"arn:aws:iam::123456789012:role/Foo",
		"arn:aws:iam::123456789012:role/Baz"}, cache.History)

	assert.Contains(t, c.GetSSO().Roles.Accounts[123456789012].Roles["Foo"].Tags, "History")
}

func (suite *CacheTestSuite) setupDeleteOldHistory() *Cache {
	c := &Cache{
		settings: &Settings{
			HistoryLimit:   2,
			HistoryMinutes: 5,
		},
		ssoName: "Default",
		SSO:     map[string]*SSOCache{},
	}
	now := time.Now().Unix()
	c.SSO["Default"] = &SSOCache{
		LastUpdate: now - 5,
		History: []string{
			"arn:aws:iam::123456789012:role/Test",
			"arn:aws:iam::123456789012:role/Foo",
		},
		Roles: &Roles{
			Accounts: map[int64]*AWSAccount{
				123456789012: {
					Roles: map[string]*AWSRole{
						"Test": {
							Tags: map[string]string{
								"History": fmt.Sprintf("MyAlias:Test,%d", now-5),
							},
						},
						"Foo": {
							Tags: map[string]string{
								"History": fmt.Sprintf("MyOtherAlias:Foo,%d", now-85),
							},
						},
					},
				},
			},
		},
	}
	return c
}

func (suite *CacheTestSuite) TestDeleteOldHistory() {
	t := suite.T()

	c := suite.setupDeleteOldHistory()

	// check setup
	assert.Equal(t, []string{
		"arn:aws:iam::123456789012:role/Test",
		"arn:aws:iam::123456789012:role/Foo",
	}, c.GetSSO().History)

	// no-op because we haven't timed out yet
	c.deleteOldHistory()
	assert.Equal(t, []string{
		"arn:aws:iam::123456789012:role/Test",
		"arn:aws:iam::123456789012:role/Foo",
	}, c.GetSSO().History)

	c = suite.setupDeleteOldHistory()

	// no-op when HistoryMinutes <= 0
	c.settings.HistoryLimit = 1
	c.settings.HistoryMinutes = 0
	c.deleteOldHistory()
	assert.Equal(t, []string{
		"arn:aws:iam::123456789012:role/Test",
		"arn:aws:iam::123456789012:role/Foo",
	}, c.GetSSO().History)

	// remove one due to HistoryLimit
	c.settings.HistoryMinutes = 1
	c.deleteOldHistory()
	assert.Equal(t, []string{
		"arn:aws:iam::123456789012:role/Test",
	}, c.GetSSO().History)
	assert.NotContains(t, "History",
		c.SSO["Default"].Roles.Accounts[123456789012].Roles["Foo"].Tags)

	// setup logger for tests
	oldLogger := log.Copy()
	tLogger := testlogger.NewTestLogger("DEBUG")
	defer tLogger.Close()
	log = tLogger

	defer func() { log = oldLogger }()

	// remove one because of HistoryMinutes expires
	c = suite.setupDeleteOldHistory()
	c.settings.HistoryMinutes = 1
	c.deleteOldHistory()

	msg := testlogger.LogMessage{}
	assert.NoError(t, tLogger.GetNext(&msg))
	assert.NotEmpty(t, msg.Message)
	assert.Equal(t, slog.LevelDebug, msg.Level)
	assert.Contains(t, "Removed expired history role", msg.Message)
	assert.Equal(t, []string{"arn:aws:iam::123456789012:role/Test"}, c.GetSSO().History)

	tLogger.Reset()
	c = suite.setupDeleteOldHistory()
	c.GetSSO().History = append(c.GetSSO().History, "arn:aws:iam:")
	c.deleteOldHistory()
	assert.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, slog.LevelDebug, msg.Level)
	assert.Contains(t, "Unable to parse History ARN", msg.Message)

	tLogger.Reset()
	c = suite.setupDeleteOldHistory()
	c.GetSSO().History = append(c.GetSSO().History, "arn:aws:iam::123456789012:role/NoHistoryTag")
	c.deleteOldHistory()
	assert.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, slog.LevelDebug, msg.Level)
	assert.Contains(t, msg.Message, "but no role by that name")

	tLogger.Reset()
	c = suite.setupDeleteOldHistory()
	c.GetSSO().History = append(c.GetSSO().History, "arn:aws:iam::1234567890:role/NoHistoryTag")
	c.deleteOldHistory()
	assert.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, slog.LevelDebug, msg.Level)
	assert.Contains(t, msg.Message, "but no account by that name")

	tLogger.Reset()
	c = suite.setupDeleteOldHistory()
	c.GetSSO().History = append(c.GetSSO().History, "arn:aws:iam::123456789012:role/NoHistoryTag")
	c.GetSSO().Roles.Accounts[123456789012].Roles["NoHistoryTag"] = &AWSRole{}
	c.deleteOldHistory()
	assert.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, slog.LevelDebug, msg.Level)
	assert.Contains(t, msg.Message, "in history list without a History tag")

	tLogger.Reset()
	c = suite.setupDeleteOldHistory()
	c.GetSSO().History = append(c.GetSSO().History, "arn:aws:iam::123456789012:role/MissingHistoryTag")
	c.GetSSO().Roles.Accounts[123456789012].Roles["MissingHistoryTag"] = &AWSRole{
		Tags: map[string]string{
			"History": "What:Foo",
		},
	}
	c.deleteOldHistory()
	assert.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, slog.LevelDebug, msg.Level)
	assert.Contains(t, msg.Message, "Too few fields for")

	tLogger.Reset()
	c = suite.setupDeleteOldHistory()
	c.GetSSO().History = append(c.GetSSO().History, "arn:aws:iam::123456789012:role/MissingHistoryTag")
	c.GetSSO().Roles.Accounts[123456789012].Roles["MissingHistoryTag"] = &AWSRole{
		Tags: map[string]string{
			"History": "What:Foo,kkkk",
		},
	}
	c.deleteOldHistory()
	assert.NoError(t, tLogger.GetNext(&msg))
	assert.Equal(t, slog.LevelDebug, msg.Level)
	assert.Contains(t, msg.Message, "Unable to parse")

	tLogger.Reset()
}

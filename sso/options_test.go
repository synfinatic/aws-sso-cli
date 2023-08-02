package sso

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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func eChecker(in string, breakline bool) bool {
	return true
}

type OptionsTestSuite struct {
	suite.Suite
	settings *Settings
}

func TestOptionsTestSuite(t *testing.T) {
	over := OverrideSettings{}
	defaults := map[string]interface{}{}
	// defined in settings_test.go
	settings, err := LoadSettings(TEST_SETTINGS_FILE, TEST_CACHE_FILE, defaults, over)
	assert.Nil(t, err)

	s := &OptionsTestSuite{
		settings: settings,
	}
	suite.Run(t, s)
}

func (suite *OptionsTestSuite) TestDefaultOptions() {
	t := suite.T()
	s := suite.settings
	opts := s.DefaultOptions(eChecker)
	assert.Equal(t, 4, len(opts))
}

func (suite *OptionsTestSuite) TestGetColorOptions() {
	t := suite.T()
	s := suite.settings
	opts := s.GetColorOptions()
	assert.Equal(t, 16, len(opts))
}

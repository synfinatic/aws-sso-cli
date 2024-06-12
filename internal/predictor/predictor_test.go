package predictor

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2023 Aaron Turner  <synfinatic at gmail dot com>
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
	// "os"
	// "fmt"
	"testing"

	// "github.com/davecgh/go-spew/spew"
	"github.com/posener/complete"
	"github.com/stretchr/testify/assert"
	// "github.com/stretchr/testify/suite"
)

func TestNewPredictor(t *testing.T) {
	p := NewPredictor("./testdata/cache.json", "./testdata/settings.yaml")
	assert.NotNil(t, p)
	assert.NotEmpty(t, p.accountids)
	assert.NotEmpty(t, p.arns)
	assert.NotEmpty(t, p.profiles)
	assert.NotEmpty(t, p.roles)

	p = NewPredictor("/dev/null", "./testdata/settings.yaml")
	assert.NotNil(t, p)
	assert.Equal(t, p.configFile, "./testdata/settings.yaml")
	assert.Empty(t, p.accountids)
	assert.Empty(t, p.arns)
	assert.Empty(t, p.profiles)
	assert.Empty(t, p.roles)

	p = NewPredictor("/dev/null", "/dev/null")
	assert.NotNil(t, p)
}

func TestCompletions(t *testing.T) {
	p := NewPredictor("./testdata/cache.json", "./testdata/settings.yaml")

	args := complete.Args{}

	c := p.AccountComplete()
	assert.NotNil(t, c)
	assert.Equal(t, 4, len(c.Predict(args)))

	c = p.FieldListComplete()
	assert.NotNil(t, c)
	assert.Equal(t, len(AllListFields), len(c.Predict(args)))

	c = p.RoleComplete()
	assert.NotNil(t, c)
	assert.Equal(t, 7, len(c.Predict(args)))

	c = p.ArnComplete()
	assert.NotNil(t, c)
	assert.Equal(t, 19, len(c.Predict(args)))

	c = p.ProfileComplete()
	assert.NotNil(t, c)
	assert.Equal(t, 19, len(c.Predict(args)))

	c = p.RegionComplete()
	assert.NotNil(t, c)
	assert.Equal(t, len(AvailableAwsRegions), len(c.Predict(args)))

	c = p.SsoComplete()
	assert.NotNil(t, c)
	assert.Equal(t, 3, len(c.Predict(args)))
}

func TestSupportedListField(t *testing.T) {
	assert.True(t, SupportedListField("AccountIdPad"))
	assert.False(t, SupportedListField("Account"))
}

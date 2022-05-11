package utils

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
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var checkValue string
var checkBrowser string

func testUrlOpener(url string) error {
	checkBrowser = "default browser"
	checkValue = url
	return nil
}

func testUrlOpenerWith(url, browser string) error {
	checkBrowser = browser
	checkValue = url
	return nil
}

func testClipboardWriter(url string) error {
	checkValue = url
	return nil
}

func testUrlOpenerError(url string) error {
	return fmt.Errorf("there was an error")
}

func testUrlOpenerWithError(url, browser string) error {
	return fmt.Errorf("there was an error")
}

func (suite *UtilsTestSuite) TestHandleUrl() {
	t := suite.T()

	noCommand := []string{}
	assert.Panics(t, func() { NewHandleUrl("foo", "browser", noCommand) })

	// override the print method
	printWriter = new(bytes.Buffer)
	h := NewHandleUrl("print", "browser", noCommand)
	assert.NotNil(t, h)
	assert.NoError(t, h.Open("bar", "pre", "post"))
	assert.Equal(t, "prebarpost", printWriter.(*bytes.Buffer).String())

	// new print method for printurl
	printWriter = new(bytes.Buffer)
	h = NewHandleUrl("printurl", "browser", noCommand)
	assert.NotNil(t, h)
	assert.NoError(t, h.Open("bar", "pre", "post"))
	assert.Equal(t, "bar\n", printWriter.(*bytes.Buffer).String())

	// Clipboard tests
	urlOpener = testUrlOpener
	urlOpenerWith = testUrlOpenerWith
	clipboardWriter = testClipboardWriter

	h = NewHandleUrl("clip", "browser", noCommand)
	assert.NotNil(t, h)
	assert.NoError(t, h.Open("url", "pre", "post"))
	assert.Equal(t, "url", checkValue)

	h = NewHandleUrl("open", "other-browser", noCommand)
	assert.NotNil(t, h)
	assert.NoError(t, h.Open("other-url", "pre", "post"))
	assert.Equal(t, "other-browser", checkBrowser)
	assert.Equal(t, "other-url", checkValue)

	h = NewHandleUrl("open", "", noCommand)
	assert.NotNil(t, h)
	assert.NoError(t, h.Open("some-url", "pre", "post"))
	assert.Equal(t, "default browser", checkBrowser)
	assert.Equal(t, "some-url", checkValue)

	urlOpener = testUrlOpenerError
	assert.Error(t, h.Open("url", "pre", "post"))

	urlOpenerWith = testUrlOpenerWithError
	h = NewHandleUrl("open", "foo", noCommand)
	assert.NotNil(t, h)
	assert.Error(t, h.Open("url", "pre", "post"))

	clipboardWriter = testUrlOpenerError
	h = NewHandleUrl("clip", "", noCommand)
	assert.NotNil(t, h)
	assert.Error(t, h.Open("url", "pre", "post"))

	// Exec tests
	h = NewHandleUrl("exec", "", []string{"echo", "foo", "%s"})
	assert.NotNil(t, h)
	assert.NoError(t, h.Open("url", "pre", "post"))

	h = NewHandleUrl("exec", "", []string{})
	assert.NotNil(t, h)
	assert.Error(t, h.Open("sh", "pre", "post"))

	h = NewHandleUrl("exec", "", []string{"%s"})
	assert.NotNil(t, h)
	assert.Error(t, h.Open("sh", "pre", "post"))

	h = NewHandleUrl("exec", "", []string{"/dev/null", "%s"})
	assert.NotNil(t, h)
	assert.Error(t, h.Open("url", "pre", "post"))

	h = NewHandleUrl("exec", "", []string{"/dev/null"})
	assert.NotNil(t, h)
	assert.Error(t, h.Open("url", "pre", "post"))

	h = NewHandleUrl("exec", "", []string{"%s"})
	assert.NotNil(t, h)
	assert.Error(t, h.Open("url", "pre", "post"))

	h = NewHandleUrl("exec", "", noCommand)
	assert.NotNil(t, h)
	assert.Error(t, h.Open("url", "pre", "post"))
}

func TestFirefoxContainersUrl(t *testing.T) {
	assert.Equal(t, "ext+container:name=Test&url=https%3A%2F%2Fsynfin.net&color=blue&icon=fingerprint",
		FirefoxContainerUrl("https://synfin.net", "Test", "blue", "fingerprint"))

	assert.Equal(t, "ext+container:name=Testy&url=https%3A%2F%2Fsynfin.net&color=turquoise&icon=briefcase",
		FirefoxContainerUrl("https://synfin.net", "Testy", "Bad", "Value"))

	assert.Equal(t, "ext+container:name=Testy&url=https%3A%2F%2Fsynfin.net&color=turquoise&icon=briefcase",
		FirefoxContainerUrl("https://synfin.net", "Testy", "", ""))
}

func TestCommandBuilder(t *testing.T) {
	_, _, err := commandBuilder([]string{}, "url")
	assert.Error(t, err)

	_, _, err = commandBuilder([]string{"foo"}, "url")
	assert.Error(t, err)

	_, _, err = commandBuilder([]string{"%s"}, "url")
	assert.Error(t, err)

	_, _, err = commandBuilder([]string{"foo", "bar"}, "url")
	assert.Error(t, err)

	cmd, l, err := commandBuilder([]string{"foo", "%s"}, "url")
	assert.NoError(t, err)
	assert.Equal(t, "foo", cmd)
	assert.Equal(t, []string{"url"}, l)

	cmd, l, err = commandBuilder([]string{"foo", "bar", "%s"}, "url")
	assert.NoError(t, err)
	assert.Equal(t, "foo", cmd)
	assert.Equal(t, []string{"bar", "url"}, l)
}

func TestSelectElement(t *testing.T) {
	check := map[string]string{
		"a":  "turquoise", // 97 % 8 => 1
		"aa": "green",     // 194 % 8 => 2
		"2d": "pink",      // 150 % 8 => 6
	}
	for k, v := range check {
		assert.Equal(t, v, selectElement(k, FIREFOX_PLUGIN_COLORS))
	}
}

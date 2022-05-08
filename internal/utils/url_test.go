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

	assert.Panics(t, func() { NewHandleUrl("foo", "browser", "") })

	// override the print method
	printWriter = new(bytes.Buffer)
	h := NewHandleUrl("print", "browser", "")
	assert.NotNil(t, h)
	assert.NoError(t, h.Open("bar", "pre", "post"))
	assert.Equal(t, "prebarpost", printWriter.(*bytes.Buffer).String())

	// new print method for printurl
	printWriter = new(bytes.Buffer)
	h = NewHandleUrl("printurl", "browser", "")
	assert.NotNil(t, h)
	assert.NoError(t, h.Open("bar", "pre", "post"))
	assert.Equal(t, "bar\n", printWriter.(*bytes.Buffer).String())

	// Clipboard tests
	urlOpener = testUrlOpener
	urlOpenerWith = testUrlOpenerWith
	clipboardWriter = testClipboardWriter

	h = NewHandleUrl("clip", "browser", "")
	assert.NotNil(t, h)
	assert.NoError(t, h.Open("url", "pre", "post"))
	assert.Equal(t, "url", checkValue)

	h = NewHandleUrl("open", "other-browser", "")
	assert.NotNil(t, h)
	assert.NoError(t, h.Open("other-url", "pre", "post"))
	assert.Equal(t, "other-browser", checkBrowser)
	assert.Equal(t, "other-url", checkValue)

	h = NewHandleUrl("open", "", "")
	assert.NotNil(t, h)
	assert.NoError(t, h.Open("some-url", "pre", "post"))
	assert.Equal(t, "default browser", checkBrowser)
	assert.Equal(t, "some-url", checkValue)

	urlOpener = testUrlOpenerError
	assert.Error(t, h.Open("url", "pre", "post"))

	urlOpenerWith = testUrlOpenerWithError
	h = NewHandleUrl("open", "foo", "")
	assert.NotNil(t, h)
	assert.Error(t, h.Open("url", "pre", "post"))

	clipboardWriter = testUrlOpenerError
	h = NewHandleUrl("clip", "", "")
	assert.NotNil(t, h)
	assert.Error(t, h.Open("url", "pre", "post"))

	// Exec tests
	h = NewHandleUrl("exec", "", []interface{}{"echo", "foo", "%s"})
	assert.NotNil(t, h)
	assert.NoError(t, h.Open("url", "pre", "post"))

	h = NewHandleUrl("exec", "", []interface{}{"%s"})
	assert.NotNil(t, h)
	assert.NoError(t, h.Open("sh", "pre", "post"))

	h = NewHandleUrl("exec", "", []interface{}{"/dev/null", "%s"})
	assert.NotNil(t, h)
	assert.Error(t, h.Open("url", "pre", "post"))

	h = NewHandleUrl("exec", "", []interface{}{"/dev/null"})
	assert.NotNil(t, h)
	assert.Error(t, h.Open("url", "pre", "post"))

	h = NewHandleUrl("exec", "", []interface{}{"%s"})
	assert.NotNil(t, h)
	assert.Error(t, h.Open("url", "pre", "post"))

	h = NewHandleUrl("exec", "", "")
	assert.NotNil(t, h)
	assert.Error(t, h.Open("url", "pre", "post"))
}

func TestFirefoxContainersUrl(t *testing.T) {
	assert.Equal(t, "ext+container:name=Test&url=https%3A%2F%2Fsynfin.net&color=blue&icon=fingerprint",
		FirefoxContainerUrl("https://synfin.net", "Test", "blue", "fingerprint"))

	assert.Equal(t, "ext+container:name=Test&url=https%3A%2F%2Fsynfin.net&color=blue&icon=fingerprint",
		FirefoxContainerUrl("https://synfin.net", "Test", "Bad", "Value"))
}

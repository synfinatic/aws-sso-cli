package url

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

	"github.com/sirupsen/logrus"
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

func TestHandleUrl(t *testing.T) {
	noCommand := []string{}
	assert.Panics(t, func() { NewHandleUrl(Exec, "foo", "browser", noCommand) })

	// override the print method
	printWriter = new(bytes.Buffer)
	h := NewHandleUrl(Print, "bar", "browser", noCommand)
	assert.NotNil(t, h)
	h.PreMsg = "pre"
	h.PostMsg = "post"
	assert.NoError(t, h.Open())
	assert.Equal(t, "prebarpost", printWriter.(*bytes.Buffer).String())

	// new print method for printurl
	printWriter = new(bytes.Buffer)
	h = NewHandleUrl(PrintUrl, "bar", "browser", noCommand)
	h.PreMsg = "pre"
	h.PostMsg = "post"
	assert.NotNil(t, h)
	assert.NoError(t, h.Open())
	assert.Equal(t, "bar\n", printWriter.(*bytes.Buffer).String())

	// Clipboard tests
	urlOpener = testUrlOpener
	urlOpenerWith = testUrlOpenerWith
	clipboardWriter = testClipboardWriter

	h = NewHandleUrl(Clip, "url", "browser", noCommand)
	assert.NotNil(t, h)
	assert.NoError(t, h.Open())
	assert.Equal(t, "url", checkValue)

	h = NewHandleUrl(Open, "other-url", "other-browser", noCommand)
	assert.NotNil(t, h)
	assert.NoError(t, h.Open())
	assert.Equal(t, "other-browser", checkBrowser)
	assert.Equal(t, "other-url", checkValue)

	h = NewHandleUrl(Open, "some-url", "", noCommand)
	assert.NotNil(t, h)
	assert.NoError(t, h.Open())
	assert.Equal(t, "default browser", checkBrowser)
	assert.Equal(t, "some-url", checkValue)

	urlOpener = testUrlOpenerError
	assert.Error(t, h.Open())

	urlOpenerWith = testUrlOpenerWithError
	h = NewHandleUrl(Open, "url", "foo", noCommand)
	assert.NotNil(t, h)
	assert.Error(t, h.Open())

	clipboardWriter = testUrlOpenerError
	h = NewHandleUrl(Clip, "url", "", noCommand)
	assert.NotNil(t, h)
	assert.Error(t, h.Open())

	// Exec tests
	h = NewHandleUrl(Exec, "url", "", []string{"echo", "foo", "%s"})
	assert.NotNil(t, h)
	assert.NoError(t, h.Open())

	assert.Panics(t, func() { NewHandleUrl(Exec, "sh", "", []string{}) })

	h = NewHandleUrl(Exec, "sh", "", []string{"%s"})
	assert.NotNil(t, h)
	assert.Error(t, h.Open())

	h = NewHandleUrl(Exec, "url", "", []string{"/dev/null", "%s"})
	assert.NotNil(t, h)
	assert.Error(t, h.Open())

	h = NewHandleUrl(Exec, "url", "", []string{"/dev/null"})
	assert.NotNil(t, h)
	assert.Error(t, h.Open())

	h = NewHandleUrl(Exec, "url", "", []string{"%s"})
	assert.NotNil(t, h)
	assert.Error(t, h.Open())

	assert.Panics(t, func() { NewHandleUrl(Exec, "url", "", noCommand) })
}

func TestFirefoxContainersUrl(t *testing.T) {
	assert.Equal(t, "ext+container:name=Test&url=https%3A%2F%2Fsynfin.net&color=blue&icon=fingerprint",
		formatContainerUrl(FIREFOX_CONTAINER_FORMAT, "https://synfin.net", "Test", "blue", "fingerprint"))

	assert.Equal(t, "ext+container:name=Testy&url=https%3A%2F%2Fsynfin.net&color=turquoise&icon=briefcase",
		formatContainerUrl(FIREFOX_CONTAINER_FORMAT, "https://synfin.net", "Testy", "Bad", "Value"))

	assert.Equal(t, "ext+granted-containers:name=Testy&url=https%3A%2F%2Fsynfin.net&color=turquoise&icon=briefcase",
		formatContainerUrl(GRANTED_CONTAINER_FORMAT, "https://synfin.net", "Testy", "", ""))
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

func TestIsContainer(t *testing.T) {
	a := Action(Open)
	assert.False(t, a.IsContainer())
	a = Exec
	assert.False(t, a.IsContainer())
	a = GrantedContainer
	assert.True(t, a.IsContainer())

	b := ConfigProfilesClip
	assert.False(t, b.IsContainer())

	b = ConfigProfilesOpenUrlContainer
	assert.True(t, b.IsContainer())
}

func TestNewAction(t *testing.T) {
	a, err := NewAction("clip")
	assert.NoError(t, err)
	assert.Equal(t, Clip, a)

	a, err = NewAction("missing")
	assert.Error(t, err)
	assert.Equal(t, Action(Open), a)

	b, err := NewConfigProfilesAction("exec")
	assert.NoError(t, err)
	assert.Equal(t, ConfigProfilesAction(ConfigProfilesExec), b)

	b, err = NewConfigProfilesAction("missing")
	assert.Error(t, err)
	assert.Equal(t, ConfigProfilesAction(ConfigProfilesOpen), b)
}

func TestLogger(t *testing.T) {
	first := GetLogger()
	defer SetLogger(first)

	log := logrus.New()
	SetLogger(log)

	l := GetLogger()
	assert.Equal(t, log, l)
}
func TestNewConfigProfilesAction(t *testing.T) {
	a, err := NewConfigProfilesAction("exec")
	assert.NoError(t, err)
	assert.Equal(t, a, ConfigProfilesAction("exec"), a)

	a, err = NewConfigProfilesAction("print")
	assert.Error(t, err)
	assert.Equal(t, a, ConfigProfilesAction("open"), a)

	a, err = NewConfigProfilesAction("invalid")
	assert.Error(t, err)
	assert.Equal(t, a, ConfigProfilesAction("open"), a)
}

func TestSSOAuthAction(t *testing.T) {
	// no change
	a, _ := NewAction("clip")
	assert.Equal(t, a, SSOAuthAction(Clip))
	a, _ = NewAction("open")
	assert.Equal(t, a, SSOAuthAction(Open))
	a, _ = NewAction("")
	assert.Equal(t, a, SSOAuthAction(Undef))
	a, _ = NewAction("print")
	assert.Equal(t, a, SSOAuthAction(Print))
	a, _ = NewAction("printurl")
	assert.Equal(t, a, SSOAuthAction(PrintUrl))
	a, _ = NewAction("exec")
	assert.Equal(t, a, SSOAuthAction(Exec))

	// change to open
	a, _ = NewAction("open")
	assert.Equal(t, a, SSOAuthAction(GrantedContainer))
	assert.Equal(t, a, SSOAuthAction(OpenUrlContainer))
}

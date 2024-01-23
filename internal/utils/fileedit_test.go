package utils

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2024 Aaron Turner  <synfinatic at gmail dot com>
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
	"os"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
)

func TestFileEdit(t *testing.T) {
	var err error
	var fe *FileEdit
	var output bytes.Buffer
	diffWriter = &output
	defer func() { diffWriter = os.Stdout }()

	var template = "{{ .Test }}"
	var vars = map[string]string{
		"Test": "foo",
	}

	_, err = NewFileEdit("{{ .Test", vars)
	assert.Error(t, err)

	fe, err = NewFileEdit(template, vars)
	assert.NoError(t, err)

	tfile, err := os.CreateTemp("", "")
	assert.NoError(t, err)
	defer os.Remove(tfile.Name())
	err = fe.UpdateConfig(true, true, tfile.Name())
	assert.NoError(t, err)
	assert.NotEmpty(t, output)
	tfile.Close()

	fBytes, err := os.ReadFile(tfile.Name())
	assert.NoError(t, err)
	assert.Equal(t, []byte(
		fmt.Sprintf(FILE_TEMPLATE, CONFIG_PREFIX, "foo", CONFIG_SUFFIX)), fBytes)

	// create the base path
	badfile := "./this/doesnt/exist"
	err = fe.UpdateConfig(false, true, badfile)
	assert.NoError(t, err)
	defer os.Remove(badfile)

	// can't treat a file like a directory though :)
	baddir := "./thisdoesntwork"
	err = os.Mkdir(baddir, 0400) // need read access to pass EnsureDirExists()
	assert.NoError(t, err)
	defer func() {
		_ = os.Chmod(baddir, 0777)
		os.Remove(baddir)
	}()
	err = fe.UpdateConfig(false, true, fmt.Sprintf("%s/foo", baddir))
	assert.Error(t, err)

	// can't create this path
	err = fe.UpdateConfig(false, true, "/cant/write/to/root/filesystem")
	assert.Error(t, err)

	// setup logger for testing
	logger, hook := test.NewNullLogger()
	logger.SetLevel(logrus.DebugLevel)
	oldLogger := GetLogger()
	SetLogger(logger)
	defer SetLogger(oldLogger)

	// check the empty diff code path
	tfile2, err := os.Open(tfile.Name())
	assert.NoError(t, err)
	err = fe.UpdateConfig(false, true, tfile2.Name())
	assert.NoError(t, err)
	assert.Contains(t, hook.LastEntry().Message, "No changes made to")

	// can't eval template
	fe, err = NewFileEdit("{{ .Test }}", []string{})
	assert.NoError(t, err)
	err = fe.UpdateConfig(false, true, tfile.Name())
	assert.Error(t, err)
}

func TestDiffBytes(t *testing.T) {
	a := []byte("foobar")
	b := []byte("foobar")

	diff := DiffBytes(a, b, "a", "b")
	assert.Empty(t, diff)

	b = []byte("foobar\nmoocow")
	diff = DiffBytes(a, b, "a", "b")
	assert.Equal(t, `--- a
+++ b
@@ -1 +1,2 @@
-foobar
\ No newline at end of file
+foobar
+moocow
\ No newline at end of file
`, diff)
}

func TestGenerateNewFile(t *testing.T) {
	var template = "{{ .Test }}"
	var vars = map[string]string{
		"Test": "foo",
	}
	fe, _ := NewFileEdit(template, vars)
	_, err := fe.GenerateNewFile("/this/directory/really/should/not/exist")
	assert.Error(t, err)
}

func promptYes(a, b string) (bool, error) {
	return true, nil
}

func promptNo(a, b string) (bool, error) {
	return false, nil
}

func promptError(a, b string) (bool, error) {
	return false, fmt.Errorf("an error")
}

func TestPrompter(t *testing.T) {
	var err error
	var fe *FileEdit

	var template = "{{ .Test }}"
	var vars = map[string]string{
		"Test": "foo",
	}

	_, err = NewFileEdit("{{ .Test", vars)
	assert.Error(t, err)

	fe, err = NewFileEdit(template, vars)
	assert.NoError(t, err)

	oldP := prompt
	defer func() { prompt = oldP }()

	tfile, err := os.CreateTemp("", "")
	assert.NoError(t, err)
	defer os.Remove(tfile.Name())
	tfile.Close()
	prompt = promptNo
	err = fe.UpdateConfig(false, false, tfile.Name())
	assert.NoError(t, err)

	fBytes, err := os.ReadFile(tfile.Name())
	assert.NoError(t, err)
	assert.Empty(t, fBytes)

	prompt = promptError
	err = fe.UpdateConfig(false, false, tfile.Name())
	assert.Error(t, err)

	prompt = promptYes
	err = fe.UpdateConfig(false, false, tfile.Name())
	assert.NoError(t, err)

	fBytes, err = os.ReadFile(tfile.Name())
	assert.NoError(t, err)
	assert.Equal(t, []byte(
		fmt.Sprintf(FILE_TEMPLATE, CONFIG_PREFIX, "foo", CONFIG_SUFFIX)), fBytes)
}

package utils

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
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileEditInvalid(t *testing.T) {
	// invalid template
	_, err := NewFileEdit("{{ .Test", "", map[string]string{})
	assert.Error(t, err)
}

func TestFileEdit(t *testing.T) {
	var err error
	var fe *FileEdit
	var output bytes.Buffer
	diffWriter = &output
	defer func() { diffWriter = os.Stdout }()

	var vars = map[string]string{
		"Test": "foo",
	}

	var template = "{{ .Test }}"
	fe, err = NewFileEdit(template, "test", vars)
	assert.NoError(t, err)

	tfile, err := os.CreateTemp("", "")
	assert.NoError(t, err)
	defer os.Remove(tfile.Name())
	changed, err := fe.UpdateConfig(true, true, tfile.Name())
	assert.NoError(t, err)
	assert.True(t, changed)
	assert.NotEmpty(t, output)
	tfile.Close()

	prefix := fmt.Sprintf("%s_%s", CONFIG_PREFIX, "test")
	suffix := fmt.Sprintf("%s_%s", CONFIG_SUFFIX, "test")
	fBytes, err := os.ReadFile(tfile.Name())
	assert.NoError(t, err)
	assert.Equal(t, []byte(fmt.Sprintf(FILE_TEMPLATE, prefix, "foo", suffix)), fBytes)

	// create the base path
	badfile := "./this/doesnt/exist"
	changed, err = fe.UpdateConfig(false, true, badfile)
	assert.NoError(t, err)
	assert.True(t, changed)
	defer os.Remove(badfile)

	// can't treat a file like a directory though :)
	baddir := "./thisdoesntwork"
	err = os.Mkdir(baddir, 0400) // need read access to pass EnsureDirExists()
	assert.NoError(t, err)
	defer func() {
		_ = os.Chmod(baddir, 0777)
		os.Remove(baddir)
	}()
	_, err = fe.UpdateConfig(false, true, fmt.Sprintf("%s/foo", baddir))
	assert.Error(t, err)

	// can't create this path
	_, err = fe.UpdateConfig(false, true, "/cant/write/to/root/filesystem")
	assert.Error(t, err)

	// check the empty diff code path
	tfile2, err := os.Open(tfile.Name())
	assert.NoError(t, err)
	changed, err = fe.UpdateConfig(false, true, tfile2.Name())
	assert.NoError(t, err)
	assert.True(t, changed)

	// can't eval template
	fe, err = NewFileEdit("{{ .Test }}", "test", []string{})
	assert.NoError(t, err)
	_, err = fe.UpdateConfig(false, true, tfile.Name())
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
	fe, _ := NewFileEdit(template, "", vars)
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

func TestDefaultFileEdit(t *testing.T) {
	var output bytes.Buffer
	diffWriter = &output
	defer func() { diffWriter = os.Stdout }()

	var vars = map[string]string{
		"Test": "foo",
	}
	var template = "{{ .Test }}"
	fe, err := NewFileEdit(template, "Default", vars)
	assert.NoError(t, err)

	tfile, err := os.CreateTemp("", "")
	assert.NoError(t, err)
	defer os.Remove(tfile.Name())
	changed, err := fe.UpdateConfig(true, true, tfile.Name())
	assert.NoError(t, err)
	assert.True(t, changed)
	assert.NotEmpty(t, output)
	tfile.Close()

	fBytes, err := os.ReadFile(tfile.Name())
	assert.NoError(t, err)
	assert.Equal(t, []byte(fmt.Sprintf(FILE_TEMPLATE, CONFIG_PREFIX, "foo", CONFIG_SUFFIX)), fBytes)
}

func TestPrompter(t *testing.T) {
	var err error
	var fe *FileEdit

	var template = "{{ .Test }}"
	var vars = map[string]string{
		"Test": "foo",
	}

	_, err = NewFileEdit("{{ .Test", "", vars)
	assert.Error(t, err)

	fe, err = NewFileEdit(template, "", vars)
	assert.NoError(t, err)

	oldP := prompt
	defer func() { prompt = oldP }()

	tfile, err := os.CreateTemp("", "")
	assert.NoError(t, err)
	defer os.Remove(tfile.Name())
	tfile.Close()
	prompt = promptNo
	changed, err := fe.UpdateConfig(false, false, tfile.Name())
	assert.NoError(t, err)
	assert.False(t, changed)

	fBytes, err := os.ReadFile(tfile.Name())
	assert.NoError(t, err)
	assert.Empty(t, fBytes)

	prompt = promptError
	_, err = fe.UpdateConfig(false, false, tfile.Name())
	assert.Error(t, err)

	prompt = promptYes
	_, err = fe.UpdateConfig(false, false, tfile.Name())
	assert.NoError(t, err)

	fBytes, err = os.ReadFile(tfile.Name())
	assert.NoError(t, err)
	assert.Equal(t, []byte(
		fmt.Sprintf(FILE_TEMPLATE, CONFIG_PREFIX, "foo", CONFIG_SUFFIX)), fBytes)
}

func TestGenerateSource(t *testing.T) {
	testcases := []struct {
		name        string
		tpl         string
		expectedErr error
		expected    string
	}{
		{
			name: "template with no variables",
			tpl: `
I'm a text template if you can believe that
`,
			expected: `
I'm a text template if you can believe that
`,
		},
		{
			name: "template",
			tpl: `
{{.Name}}
`,
			expected: `
template
`,
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			output, err := GenerateSource(tc.tpl, map[string]interface{}{
				"Name": tc.name,
			})
			require.Equal(t, tc.expectedErr, err)
			require.Equal(t, tc.expected, string(output))
		})
	}
}

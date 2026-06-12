package helper

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSourceHelper(t *testing.T) {
	testcases := []struct {
		shell           string
		expectedError   error
		expectedOutputs [][]byte
	}{
		{
			shell: "bash",
			expectedOutputs: [][]byte{[]byte(`
complete -F __aws_sso_profile_complete aws-sso-profile
complete -C /bin/aws-sso-cli aws-sso
`)},
		},
		{
			shell: "zsh",
			expectedOutputs: [][]byte{[]byte(`
compdef __aws_sso_profile_complete aws-sso-profile
complete -C /bin/aws-sso-cli aws-sso
`)},
		},
		{
			shell: "fish",
			expectedOutputs: [][]byte{
				[]byte(`function __complete_aws-sso`),
				[]byte(`complete -f -c aws-sso -a "(__complete_aws-sso)"`),
				[]byte(`function aws-sso-profile`),
				[]byte(`function __aws_sso_profile_complete`),
				[]byte(`complete -f -c aws-sso-profile`),
				[]byte(`function aws-sso-clear`),
				[]byte(`/bin/aws-sso-cli`),
			},
		},
		{
			shell:         "nushell",
			expectedError: errors.New("unsupported shell: nushell"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.shell, func(t *testing.T) {
			t.Parallel()
			var (
				output = bytes.NewBuffer(nil)
				h      = &SourceHelper{
					getExe: func() (string, error) {
						return "/bin/aws-sso-cli", nil
					},
					output: output,
				}
			)

			err := h.Generate(tc.shell)
			require.Equal(t, tc.expectedError, err)
			for _, expected := range tc.expectedOutputs {
				require.Contains(t, output.String(), string(bytes.TrimLeftFunc(expected, unicode.IsSpace)))
			}
		})
	}
}

func TestConfigFiles(t *testing.T) {
	t.Parallel()
	files := ConfigFiles()
	require.Len(t, files, 6)
}

func TestNewSourceHelper(t *testing.T) {
	t.Parallel()
	f := func() (string, error) {
		return "", nil
	}
	h := NewSourceHelper(f, os.Stdout)
	assert.NotNil(t, h)
}

func TestGetFishPaths(t *testing.T) {
	t.Parallel()
	assert.Contains(t, getFishCompletionPath("aws-sso.fish"), path.Join("fish", "completions", "aws-sso.fish"))
	assert.Contains(t, getFishFunctionPath("aws-sso-profile.fish"), path.Join("fish", "functions", "aws-sso-profile.fish"))
}

func TestDetectShellBash(t *testing.T) {
	t.Parallel()
	shell, err := detectShell()
	assert.NoError(t, err)
	assert.NotEmpty(t, shell)
}

func TestGenerate(t *testing.T) {
	t.Parallel()
	buf := bytes.Buffer{}
	_ = io.Writer(&buf)

	sh := &SourceHelper{
		getExe: func() (string, error) {
			return "/usr/local/bin/aws-sso", nil
		},
		output: &buf,
	}
	err := sh.Generate("bash")
	assert.NoError(t, err)
	assert.NotEmpty(t, buf.String())
}
func TestPrintConfig(t *testing.T) {
	t.Parallel()
	scripts, err := getScripts("bash")
	assert.NoError(t, err)
	require.Len(t, scripts, 1)
	c := scripts[0].contents
	p := scripts[0].path
	assert.NotEmpty(t, c)
	assert.NotEmpty(t, p)
	assert.Contains(t, string(c), "{{ .Executable }}") // this is a template

	buf := bytes.Buffer{}
	_ = io.Writer(&buf)
	err = printConfig(c, "/usr/local/bin/aws-sso", &buf)
	assert.NoError(t, err)
	output := buf.String()
	assert.NotContains(t, output, "{{ .Executable }}")
	assert.Contains(t, output, "/usr/local/bin/aws-sso")

	buf.Reset()
	err = printConfig([]byte{}, "", &buf)
	assert.Error(t, err)
}

func TestInstallHelper(t *testing.T) {
	t.Parallel()
	err := UninstallHelper("foobar", "")
	assert.Error(t, err)

	forceIt = true
	defer func() { forceIt = false }()

	tempFile, err := os.CreateTemp("", "")
	assert.NoError(t, err)
	defer os.Remove(tempFile.Name())

	err = InstallHelper("bash", tempFile.Name())
	assert.NoError(t, err)

	err = UninstallHelper("bash", tempFile.Name())
	assert.NoError(t, err)
}

func TestInstallFish(t *testing.T) {
	forceIt = true
	defer func() { forceIt = false }()

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	err := InstallHelper("fish", "")
	require.NoError(t, err)

	fishBase := getFishBase()
	expectedFiles := []string{
		path.Join(fishBase, "completions", "aws-sso.fish"),
		path.Join(fishBase, "functions", "aws-sso-profile.fish"),
		path.Join(fishBase, "completions", "aws-sso-profile.fish"),
		path.Join(fishBase, "functions", "aws-sso-clear.fish"),
	}
	for _, f := range expectedFiles {
		info, statErr := os.Stat(f)
		require.NoError(t, statErr, "expected file to exist: %s", f)
		assert.Greater(t, info.Size(), int64(0))
	}

	err = UninstallHelper("fish", "")
	require.NoError(t, err)
	for _, f := range expectedFiles {
		_, statErr := os.Stat(f)
		assert.True(t, os.IsNotExist(statErr), "expected file to be removed: %s", f)
	}
}

func TestFishFilesContent(t *testing.T) {
	t.Parallel()
	scripts, err := getScripts("fish")
	require.NoError(t, err)
	require.Len(t, scripts, 4)

	combined := ""
	for _, s := range scripts {
		combined += string(s.contents)
	}
	assert.Contains(t, combined, "function aws-sso-profile")
	assert.Contains(t, combined, "function aws-sso-clear")
	assert.Contains(t, combined, "function __complete_aws-sso")
	assert.Contains(t, combined, "function __aws_sso_profile_complete")
}

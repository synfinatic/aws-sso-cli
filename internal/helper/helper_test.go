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
		shell          string
		expectedError  error
		expectedOutput []byte
	}{
		{
			shell: "bash",
			expectedOutput: []byte(`
complete -F __aws_sso_profile_complete aws-sso-profile
complete -C /bin/aws-sso-cli aws-sso
`),
		},
		{
			shell: "zsh",
			expectedOutput: []byte(`
compdef __aws_sso_profile_complete aws-sso-profile
complete -C /bin/aws-sso-cli aws-sso
`),
		},
		{
			shell: "fish",
			expectedOutput: []byte(`
function __complete_aws-sso
    set -lx COMP_LINE (commandline -cp)
    test -z (commandline -ct)
    and set COMP_LINE "$COMP_LINE "
    export __NO_ESCAPE_COLONS=1
    /bin/aws-sso-cli
end
complete -f -c aws-sso -a "(__complete_aws-sso)"
`),
		},
		{
			shell:         "nushell",
			expectedError: errors.New("unsupported shell: nushell"),
		},
	}

	for _, tc := range testcases {
		tc := tc

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
			require.Contains(t, output.String(), string(bytes.TrimLeftFunc(tc.expectedOutput, unicode.IsSpace)))
		})
	}
}

func TestConfigFiles(t *testing.T) {
	t.Parallel()
	files := ConfigFiles()
	require.Len(t, files, 3)
}

func TestNewSourceHelper(t *testing.T) {
	t.Parallel()
	f := func() (string, error) {
		return "", nil
	}
	h := NewSourceHelper(f, os.Stdout)
	assert.NotNil(t, h)
}

func TestGetFishScript(t *testing.T) {
	t.Parallel()
	f := getFishScript()
	assert.Contains(t, f, path.Join("fish", "completions", "aws-sso.fish"))
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
	c, p, err := getScript("bash")
	assert.NoError(t, err)
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

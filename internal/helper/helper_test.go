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

// TestFishUninstallPreservesUserContent verifies that UninstallHelper for fish
// removes only the managed block and preserves any user content outside it.
func TestFishUninstallPreservesUserContent(t *testing.T) {
	forceIt = true
	defer func() { forceIt = false }()

	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	require.NoError(t, InstallHelper("fish", ""))

	fishBase := getFishBase()
	profileFile := path.Join(fishBase, "functions", "aws-sso-profile.fish")
	clearFile := path.Join(fishBase, "functions", "aws-sso-clear.fish")

	// Append user content after the managed block in one file.
	existing, err := os.ReadFile(profileFile)
	require.NoError(t, err)
	userContent := "# my custom addition\nset MY_FISH_VAR hello\n"
	err = os.WriteFile(profileFile, append(existing, []byte(userContent)...), 0600)
	require.NoError(t, err)

	require.NoError(t, UninstallHelper("fish", ""))

	// File with user content must survive and contain only the user addition.
	remaining, readErr := os.ReadFile(profileFile)
	require.NoError(t, readErr, "file with user content should not be deleted")
	assert.Contains(t, string(remaining), "my custom addition")
	assert.NotContains(t, string(remaining), "function aws-sso-profile")

	// File without user content must be fully removed.
	_, statErr := os.Stat(clearFile)
	assert.True(t, os.IsNotExist(statErr), "file without user content should be removed")
}

// TestNewSourceHelperParams verifies that NewSourceHelper actually uses the
// getExe and output arguments it receives.
func TestNewSourceHelperParams(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	called := false
	getExe := func() (string, error) {
		called = true
		return "/custom/aws-sso", nil
	}
	h := NewSourceHelper(getExe, &buf)
	require.NoError(t, h.Generate("bash"))
	assert.True(t, called, "getExe should have been called")
	assert.Contains(t, buf.String(), "/custom/aws-sso")
}

// TestGetScriptsAutoDetect verifies that passing "" auto-detects the shell
// without returning an error.
func TestGetScriptsAutoDetect(t *testing.T) {
	t.Parallel()
	scripts, err := getScripts("")
	assert.NoError(t, err)
	assert.NotEmpty(t, scripts)
}

// TestGenerateGetExeError covers the getExe error path in Generate.
func TestGenerateGetExeError(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	h := &SourceHelper{
		getExe: func() (string, error) { return "", errors.New("no exe") },
		output: &buf,
	}
	err := h.Generate("bash")
	assert.Error(t, err)
}

// TestInstallHelperUnsupportedShell covers the getScripts error return in InstallHelper.
func TestInstallHelperUnsupportedShell(t *testing.T) {
	t.Parallel()
	err := InstallHelper("nushell", "")
	assert.Error(t, err)
}

// failWriter is an io.Writer that always returns an error.
type failWriter struct{}

func (failWriter) Write(_ []byte) (int, error) { return 0, errors.New("write failed") }

// TestPrintConfigWriteError covers the "no data written" path in printConfig.
func TestPrintConfigWriteError(t *testing.T) {
	t.Parallel()
	scripts, err := getScripts("bash")
	require.NoError(t, err)
	err = printConfig(scripts[0].contents, "/usr/local/bin/aws-sso", failWriter{})
	assert.Error(t, err)
}

// TestRemoveFishFileNonExistent covers the os.ReadFile error (IsNotExist) path.
func TestRemoveFishFileNonExistent(t *testing.T) {
	t.Parallel()
	// Must not panic or log a warning — silent return on NotExist.
	removeFishFile("/nonexistent/fish/file.fish")
}

// TestRemoveBlock validates the block-stripping helper used by removeFishFile.
func TestRemoveBlock(t *testing.T) {
	t.Parallel()
	const prefix = "# BEGIN_AWS_SSO_CLI"
	const suffix = "# END_AWS_SSO_CLI"

	managed := []byte(prefix + "\ncontent line\n" + suffix + "\n")

	// File is only the managed block → result is empty.
	out := removeBlock(managed, prefix, suffix)
	assert.Empty(t, bytes.TrimSpace(out))

	// User content before the block is preserved.
	withBefore := append([]byte("user before\n"), managed...)
	out = removeBlock(withBefore, prefix, suffix)
	assert.Contains(t, string(out), "user before")
	assert.NotContains(t, string(out), "content line")

	// User content after the block is preserved.
	withAfter := append(managed, []byte("user after\n")...)
	out = removeBlock(withAfter, prefix, suffix)
	assert.Contains(t, string(out), "user after")
	assert.NotContains(t, string(out), "content line")
}

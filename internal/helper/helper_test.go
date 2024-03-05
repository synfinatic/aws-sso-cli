package helper

import (
	"bytes"
	"errors"
	"testing"
	"unicode"

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

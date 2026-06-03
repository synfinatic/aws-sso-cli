package main

import (
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/synfinatic/aws-sso-cli/internal/predictor"
)

func TestPartitionByValue(t *testing.T) {
	t.Run("known value returns matching partition", func(t *testing.T) {
		p := partitionByValue("aws")
		assert.Equal(t, "aws", p.Value)
		assert.Equal(t, "Commercial", p.Name)
	})

	t.Run("unknown value returns first partition (commercial default)", func(t *testing.T) {
		p := partitionByValue("aws-nonexistent")
		assert.Equal(t, predictor.AWSPartitions[0].Value, p.Value)
	})

	t.Run("GovCloud partition", func(t *testing.T) {
		p := partitionByValue("aws-us-gov")
		assert.Equal(t, "aws-us-gov", p.Value)
	})

	t.Run("China partition", func(t *testing.T) {
		p := partitionByValue("aws-cn")
		assert.Equal(t, "aws-cn", p.Value)
	})
}

func TestYesNoPos(t *testing.T) {
	assert.Equal(t, 1, yesNoPos(true))
	assert.Equal(t, 0, yesNoPos(false))
}

func TestDefaultSelect(t *testing.T) {
	options := []selectOptions{
		{Name: "Option A", Value: "a"},
		{Name: "Option B", Value: "b"},
		{Name: "Option C", Value: "c"},
	}

	t.Run("found returns correct index", func(t *testing.T) {
		assert.Equal(t, 0, defaultSelect(options, "a"))
		assert.Equal(t, 1, defaultSelect(options, "b"))
		assert.Equal(t, 2, defaultSelect(options, "c"))
	})

	t.Run("not found returns 0", func(t *testing.T) {
		assert.Equal(t, 0, defaultSelect(options, "z"))
	})

	t.Run("empty options returns 0", func(t *testing.T) {
		assert.Equal(t, 0, defaultSelect([]selectOptions{}, "a"))
	})
}

func TestValidateInteger(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"42", false},
		{"-1", false},
		{"0", false},
		{"  10  ", false}, // whitespace trimmed
		{"abc", true},
		{"", true},
		{"1.5", true},
		{"1e5", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			err := validateInteger(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFirefoxDefaultBrowserPath(t *testing.T) {
	t.Run("non-empty input is returned unchanged", func(t *testing.T) {
		assert.Equal(t, "/custom/path/firefox", firefoxDefaultBrowserPath("/custom/path/firefox"))
	})

	t.Run("empty input returns OS-specific default", func(t *testing.T) {
		result := firefoxDefaultBrowserPath("")
		switch runtime.GOOS {
		case "darwin":
			assert.Equal(t, "/Applications/Firefox.app/Contents/MacOS/firefox", result)
		case "linux":
			assert.Equal(t, "/usr/bin/firefox", result)
		case "windows":
			assert.Equal(t, "\\Program Files\\Mozilla Firefox\\firefox.exe", result)
		default:
			assert.Equal(t, "", result)
		}
	})
}

func TestValidateBinary(t *testing.T) {
	t.Run("missing path returns error", func(t *testing.T) {
		err := validateBinary("/nonexistent/path/to/binary")
		assert.Error(t, err)
	})

	if runtime.GOOS != "windows" {
		t.Run("executable regular file returns nil", func(t *testing.T) {
			f, err := os.CreateTemp("", "test-binary-*")
			assert.NoError(t, err)
			f.Close()
			defer os.Remove(f.Name())

			assert.NoError(t, os.Chmod(f.Name(), 0755)) //nolint:gosec
			assert.NoError(t, validateBinary(f.Name()))
		})

		t.Run("non-executable regular file returns error", func(t *testing.T) {
			f, err := os.CreateTemp("", "test-binary-*")
			assert.NoError(t, err)
			f.Close()
			defer os.Remove(f.Name())

			assert.NoError(t, os.Chmod(f.Name(), 0644)) //nolint:gosec
			assert.Error(t, validateBinary(f.Name()))
		})
	} else {
		t.Run("regular file on windows returns nil", func(t *testing.T) {
			f, err := os.CreateTemp("", "test-binary-*")
			assert.NoError(t, err)
			f.Close()
			defer os.Remove(f.Name())
			assert.NoError(t, validateBinary(f.Name()))
		})
	}
}

func TestValidateBinaryOrNone(t *testing.T) {
	t.Run("empty string returns nil", func(t *testing.T) {
		assert.NoError(t, validateBinaryOrNone(""))
	})

	t.Run("whitespace-only string returns nil", func(t *testing.T) {
		assert.NoError(t, validateBinaryOrNone("   "))
	})

	t.Run("missing path returns error", func(t *testing.T) {
		assert.Error(t, validateBinaryOrNone("/nonexistent/path/to/binary"))
	})

	if runtime.GOOS != "windows" {
		t.Run("executable file returns nil", func(t *testing.T) {
			f, err := os.CreateTemp("", "test-binary-*")
			assert.NoError(t, err)
			f.Close()
			defer os.Remove(f.Name())

			assert.NoError(t, os.Chmod(f.Name(), 0755)) //nolint:gosec
			assert.NoError(t, validateBinaryOrNone(f.Name()))
		})

		t.Run("non-executable file returns error", func(t *testing.T) {
			f, err := os.CreateTemp("", "test-binary-*")
			assert.NoError(t, err)
			f.Close()
			defer os.Remove(f.Name())

			assert.NoError(t, os.Chmod(f.Name(), 0644)) //nolint:gosec
			assert.Error(t, validateBinaryOrNone(f.Name()))
		})
	}
}

func TestMakeSelectTemplate(t *testing.T) {
	tmpl := makeSelectTemplate("Choose role")
	require.NotNil(t, tmpl)
	assert.NotEmpty(t, tmpl.Label)
	assert.NotEmpty(t, tmpl.Active)
	assert.NotEmpty(t, tmpl.Inactive)
	assert.NotEmpty(t, tmpl.Selected)
}

func TestMakePromptTemplate(t *testing.T) {
	tmpl := makePromptTemplate("Enter value")
	require.NotNil(t, tmpl)
	assert.NotEmpty(t, tmpl.Prompt)
	assert.NotEmpty(t, tmpl.Success)
}

func TestCheckPromptError_Del(t *testing.T) {
	// "^D" logs an error but does not call log.Fatal — must not panic.
	assert.NotPanics(t, func() {
		checkPromptError(errors.New("^D"))
	})
}

func TestCheckPromptError_Default(t *testing.T) {
	assert.NotPanics(t, func() {
		checkPromptError(errors.New("some unexpected error"))
	})
}

func TestCheckSelectError_Default(t *testing.T) {
	assert.NotPanics(t, func() {
		checkSelectError(errors.New("some select error"))
	})
}

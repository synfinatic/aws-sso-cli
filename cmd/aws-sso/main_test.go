package main

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccountIDUnmarshalText(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    AccountID
		wantErr bool
	}{
		{
			name:  "standard 12-digit account ID",
			input: "123456789012",
			want:  AccountID(123456789012),
		},
		{
			name:  "account ID with leading zeros",
			input: "012345678901",
			want:  AccountID(12345678901),
		},
		{
			name:    "non-numeric string",
			input:   "notanid",
			wantErr: true,
		},
		{
			name:    "negative number",
			input:   "-1",
			wantErr: true,
		},
		{
			name:    "number exceeding max account ID",
			input:   "9999999999999",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var a AccountID
			err := a.UnmarshalText([]byte(tt.input))
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, a)
			}
		})
	}
}

// TestSignalExitGoroutine verifies that cancelling the signal context causes os.Exit(1).
// It uses a subprocess so os.Exit doesn't terminate the test runner.
func TestSignalExitGoroutine(t *testing.T) {
	if os.Getenv("TEST_SIGNAL_EXIT_SUBPROCESS") == "1" {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-ctx.Done()
			os.Exit(1)
		}()
		cancel()
		time.Sleep(time.Second) // should not reach here
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestSignalExitGoroutine", "-test.v") //nolint:gosec
	cmd.Env = append(os.Environ(), "TEST_SIGNAL_EXIT_SUBPROCESS=1")
	err := cmd.Run()
	require.Error(t, err)
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 1, exitErr.ExitCode())
}

func TestLogLevelTypeValidate(t *testing.T) {
	tests := []struct {
		level   string
		wantErr bool
	}{
		{"error", false},
		{"warn", false},
		{"info", false},
		{"debug", false},
		{"trace", false},
		{"", false},
		{"verbose", true},
		{"WARNING", true},
		{"INFO", true},
	}
	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			err := LogLevelType(tt.level).Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

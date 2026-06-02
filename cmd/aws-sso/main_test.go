package main

import (
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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

// TestWatchSignalsCleanStopDoesNotExit is the regression test for the credential_process
// exit-code bug: a clean shutdown (the deferred stop() on a successful run) must NOT
// trigger the hard-exit goroutine. Otherwise even successful commands exit non-zero and
// `aws-sso process` becomes unusable as an AWS credential_process.
//
// With the buggy wiring (goroutine watching appCtx.Done()) stop() cancels the context and
// the goroutine calls os.Exit(1); with the fix (goroutine watching a dedicated signal
// channel) stop() is a no-op for the exit path.
func TestWatchSignalsCleanStopDoesNotExit(t *testing.T) {
	orig := osExit
	var exited int32
	osExit = func(int) { atomic.StoreInt32(&exited, 1) }
	t.Cleanup(func() { osExit = orig })

	_, stop := watchSignals()
	stop()                             // normal, successful-exit path
	time.Sleep(100 * time.Millisecond) // give the goroutine time to (wrongly) fire

	assert.Equal(t, int32(0), atomic.LoadInt32(&exited),
		"a clean stop() must not call os.Exit -- would break credential_process")
}

// TestHardExitOnSignalExitsOnSignal verifies the intended behaviour from #1379: an actual
// signal forces os.Exit(1). It feeds the signal channel directly, so no real OS signal is
// sent and the test never touches AWS, the keyring, or the network.
func TestHardExitOnSignalExitsOnSignal(t *testing.T) {
	orig := osExit
	done := make(chan int, 1)
	osExit = func(code int) { done <- code }
	t.Cleanup(func() { osExit = orig })

	sigCh := make(chan os.Signal, 1)
	go hardExitOnSignal(sigCh)
	sigCh <- syscall.SIGINT

	select {
	case code := <-done:
		assert.Equal(t, 1, code)
	case <-time.After(2 * time.Second):
		t.Fatal("expected os.Exit(1) after receiving a signal")
	}
}

// TestHardExitOnSignalDoesNotExitOnClose verifies that closing sigCh (the stop() path)
// causes hardExitOnSignal to return without calling osExit — fixing the goroutine leak.
func TestHardExitOnSignalDoesNotExitOnClose(t *testing.T) {
	orig := osExit
	var exited int32
	osExit = func(int) { atomic.StoreInt32(&exited, 1) }
	t.Cleanup(func() { osExit = orig })

	sigCh := make(chan os.Signal, 1)
	returned := make(chan struct{})
	go func() {
		hardExitOnSignal(sigCh)
		close(returned)
	}()
	close(sigCh)

	select {
	case <-returned:
		assert.Equal(t, int32(0), atomic.LoadInt32(&exited),
			"closing the signal channel must not call os.Exit")
	case <-time.After(2 * time.Second):
		t.Fatal("hardExitOnSignal did not return after channel was closed")
	}
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

package main

import (
	"testing"

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

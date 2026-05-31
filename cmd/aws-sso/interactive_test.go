package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArgsToMap(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantTags map[string]string
		wantKey  string
		wantVal  string
	}{
		{
			name:     "empty slice",
			args:     []string{},
			wantTags: map[string]string{},
			wantKey:  "",
			wantVal:  "",
		},
		{
			name:     "single word",
			args:     []string{"env"},
			wantTags: map[string]string{},
			wantKey:  "env",
			wantVal:  "",
		},
		{
			name:     "two words with trailing empty: complete pair",
			args:     []string{"key", "val", ""},
			wantTags: map[string]string{"key": "val"},
			wantKey:  "",
			wantVal:  "",
		},
		{
			name:     "two words no trailing: incomplete value also returned in map",
			args:     []string{"key", "val"},
			wantTags: map[string]string{"key": "val"},
			wantKey:  "key",
			wantVal:  "val",
		},
		{
			name: "one complete pair plus incomplete key: pair is dropped (existing behavior)",
			args: []string{"k1", "v1", "k2"},
			// NOTE: k1→v1 is dropped by the existing loop logic (i < len(cleanArgs)-2 when len=2 → i<0)
			wantTags: map[string]string{},
			wantKey:  "k2",
			wantVal:  "",
		},
		{
			name:     "two pairs with trailing empty: both complete",
			args:     []string{"k1", "v1", "k2", "v2", ""},
			wantTags: map[string]string{"k1": "v1", "k2": "v2"},
			wantKey:  "",
			wantVal:  "",
		},
		{
			name:     "two pairs no trailing: last pair also returned as retKey/retVal",
			args:     []string{"k1", "v1", "k2", "v2"},
			wantTags: map[string]string{"k1": "v1", "k2": "v2"},
			wantKey:  "k2",
			wantVal:  "v2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTags, gotKey, gotVal := argsToMap(tt.args)
			assert.Equal(t, tt.wantTags, gotTags)
			assert.Equal(t, tt.wantKey, gotKey)
			assert.Equal(t, tt.wantVal, gotVal)
		})
	}
}

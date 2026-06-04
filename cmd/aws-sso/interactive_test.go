package main

import (
	"testing"

	"github.com/c-bata/go-prompt"
	"github.com/stretchr/testify/assert"
	ssocache "github.com/synfinatic/aws-sso-cli/internal/sso/cache"
	"github.com/synfinatic/aws-sso-cli/internal/tags"
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

func TestCompleteTags(t *testing.T) {
	const (
		arn1  = "arn:aws:iam::111111111111:role/Admin"
		arn2  = "arn:aws:iam::222222222222:role/ReadOnly"
		arn3  = "arn:aws:iam::333333333333:role/Viewer"
		prof1 = "111111111111:Admin"
		prof2 = "222222222222:ReadOnly"
		prof3 = "333333333333:Viewer"
	)

	rt := ssocache.RoleTags{
		arn1: {"env": "prod"},
		arn2: {"env": "dev"},
		arn3: {"env": "dev"},
	}
	tl := tags.TagsList{
		"env": {"dev", "prod"},
	}
	profiles := map[string]string{
		prof1: arn1,
		prof2: arn2,
		prof3: arn3,
	}

	suggestTexts := func(suggests []prompt.Suggest) []string {
		texts := make([]string, len(suggests))
		for i, s := range suggests {
			texts[i] = s.Text
		}
		return texts
	}

	t.Run("empty args shows ProfileName key not individual profiles", func(t *testing.T) {
		got := completeTags(&rt, &tl, []string{}, []string{}, "", profiles)
		texts := suggestTexts(got)
		assert.Contains(t, texts, "ProfileName")
		assert.NotContains(t, texts, prof1)
		assert.NotContains(t, texts, prof2)
		assert.NotContains(t, texts, prof3)
	})

	t.Run("top-level tag keys and ProfileName are in sorted order", func(t *testing.T) {
		// "ProfileName" (uppercase P=0x50) sorts before "env" (lowercase e=0x65)
		got := completeTags(&rt, &tl, []string{}, []string{}, "", profiles)
		texts := suggestTexts(got)
		assert.Equal(t, []string{"ProfileName", "env"}, texts)
	})

	t.Run("ProfileName description follows roles/choices pattern", func(t *testing.T) {
		got := completeTags(&rt, &tl, []string{}, []string{}, "", profiles)
		for _, s := range got {
			if s.Text == "ProfileName" {
				assert.Equal(t, "3 roles/3 choices", s.Description)
				return
			}
		}
		t.Fatal("ProfileName suggestion not found")
	})

	t.Run("ProfileName key absent after tag selection", func(t *testing.T) {
		// Once a tag has been selected, ProfileName is no longer a top-level option.
		got := completeTags(&rt, &tl, []string{}, []string{"env", "dev", ""}, "", profiles)
		texts := suggestTexts(got)
		assert.NotContains(t, texts, "ProfileName")
	})

	t.Run("nextKey ProfileName shows all profile names with ARN descriptions", func(t *testing.T) {
		// user typed "ProfileName " → nextKey="ProfileName", nextValue=""
		got := completeTags(&rt, &tl, []string{}, []string{"ProfileName", ""}, "", profiles)
		texts := suggestTexts(got)
		assert.Contains(t, texts, prof1)
		assert.Contains(t, texts, prof2)
		assert.Contains(t, texts, prof3)
		for _, s := range got {
			assert.Equal(t, profiles[s.Text], s.Description)
		}
	})

	t.Run("profile suggestions are returned in sorted order", func(t *testing.T) {
		got := completeTags(&rt, &tl, []string{}, []string{"ProfileName", ""}, "", profiles)
		texts := suggestTexts(got)
		assert.Equal(t, []string{prof1, prof2, prof3}, texts)
	})

	t.Run("nextKey ProfileName with partial value filters profile names", func(t *testing.T) {
		// user typed "ProfileName 222" → nextKey="ProfileName", nextValue="222"
		got := completeTags(&rt, &tl, []string{}, []string{"ProfileName", "222"}, "", profiles)
		texts := suggestTexts(got)
		assert.Contains(t, texts, prof2)
		assert.NotContains(t, texts, prof1)
		assert.NotContains(t, texts, prof3)
	})

	t.Run("nextKey ProfileName shows all profiles when only one prior pair exists", func(t *testing.T) {
		// argsToMap drops the completed "env dev" pair when nextKey is present (existing
		// behavior for odd-length cleanArgs), so all profiles are shown unfiltered.
		got := completeTags(&rt, &tl, []string{}, []string{"env", "dev", "ProfileName", ""}, "", profiles)
		texts := suggestTexts(got)
		assert.Contains(t, texts, prof1)
		assert.Contains(t, texts, prof2)
		assert.Contains(t, texts, prof3)
	})

	t.Run("completed ProfileName selection returns empty", func(t *testing.T) {
		// user selected "ProfileName 111111111111:Admin " (complete) → empty, executor fires
		got := completeTags(&rt, &tl, []string{}, []string{"ProfileName", prof1, ""}, "", profiles)
		assert.Empty(t, got)
	})

	t.Run("filtered to single role by tags returns empty", func(t *testing.T) {
		// "env prod " = env:prod selected, only Admin matches → early return
		got := completeTags(&rt, &tl, []string{}, []string{"env", "prod", ""}, "", profiles)
		assert.Empty(t, got)
	})
}

func TestRoleDescription(t *testing.T) {
	const arn = "arn:aws:iam::111111111111:role/Admin"
	rt := ssocache.RoleTags{
		arn: {"env": "prod", "AccountAlias": "prod-account"},
	}

	tests := []struct {
		name               string
		args               []string
		accountPrimaryTags []string
		want               string
	}{
		{
			name:               "no args returns first primary tag value",
			args:               []string{},
			accountPrimaryTags: []string{"env"},
			want:               "env:prod",
		},
		{
			name:               "tag already in args is skipped",
			args:               []string{"env", "prod", ""},
			accountPrimaryTags: []string{"env", "AccountAlias"},
			want:               "AccountAlias:prod-account",
		},
		{
			name:               "all primary tags selected returns empty string",
			args:               []string{"env", "prod", ""},
			accountPrimaryTags: []string{"env"},
			want:               "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := roleDescription(arn, tt.args, tt.accountPrimaryTags, &rt)
			assert.Equal(t, tt.want, got)
		})
	}
}

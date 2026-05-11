package ui

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2026 Aaron Turner  <synfinatic at gmail dot com>
 *
 * This program is free software: you can redistribute it
 * and/or modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or with the authors permission any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func exitChecker(in string, breakLine bool) bool { return true }

func defaultColors() PromptColors {
	return PromptColors{
		DescriptionBGColor:           "DefaultColor",
		DescriptionTextColor:         "DefaultColor",
		InputBGColor:                 "DefaultColor",
		InputTextColor:               "DefaultColor",
		PrefixBackgroundColor:        "DefaultColor",
		PrefixTextColor:              "DefaultColor",
		PreviewSuggestionBGColor:     "DefaultColor",
		PreviewSuggestionTextColor:   "DefaultColor",
		ScrollbarBGColor:             "DefaultColor",
		ScrollbarThumbColor:          "DefaultColor",
		SelectedDescriptionBGColor:   "DefaultColor",
		SelectedDescriptionTextColor: "DefaultColor",
		SelectedSuggestionBGColor:    "DefaultColor",
		SelectedSuggestionTextColor:  "DefaultColor",
		SuggestionBGColor:            "DefaultColor",
		SuggestionTextColor:          "DefaultColor",
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions(exitChecker)
	assert.Equal(t, 4, len(opts))
}

func TestGetColorOptions(t *testing.T) {
	opts := GetColorOptions(defaultColors())
	assert.Equal(t, 16, len(opts))
}

func TestGetColorOptionsAllColors(t *testing.T) {
	// Verify every named color resolves without panicking.
	for _, colorName := range []string{
		"DefaultColor", "Black", "DarkRed", "DarkGreen", "Brown",
		"DarkBlue", "Purple", "Cyan", "LightGrey", "DarkGrey", "DarkGray",
		"Red", "Green", "Yellow", "Blue", "Fuchsia", "Turquoise", "White",
	} {
		c := defaultColors()
		c.DescriptionBGColor = colorName
		opts := GetColorOptions(c)
		assert.Equal(t, 16, len(opts), "color: %s", colorName)
	}
}

func TestPromptColorFuncsCompleteness(t *testing.T) {
	// Every PromptColors field must have a matching entry in PromptColorFuncs.
	rt := reflect.TypeOf(PromptColors{})
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i).Name
		key := "Option" + field
		_, ok := PromptColorFuncs[key]
		assert.True(t, ok, "missing PromptColorFuncs entry: %s", key)
	}
}

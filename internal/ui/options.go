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
	"fmt"
	"reflect"

	"github.com/c-bata/go-prompt"
)

// PromptColors holds color configuration for the interactive CLI prompt.
type PromptColors struct {
	DescriptionBGColor           string
	DescriptionTextColor         string
	InputBGColor                 string
	InputTextColor               string
	PrefixBackgroundColor        string
	PrefixTextColor              string
	PreviewSuggestionBGColor     string
	PreviewSuggestionTextColor   string
	ScrollbarBGColor             string
	ScrollbarThumbColor          string
	SelectedDescriptionBGColor   string
	SelectedDescriptionTextColor string
	SelectedSuggestionBGColor    string
	SelectedSuggestionTextColor  string
	SuggestionBGColor            string
	SuggestionTextColor          string
}

type ColorOptionFunction func(prompt.Color) prompt.Option

var PromptColorFuncs map[string]ColorOptionFunction = map[string]ColorOptionFunction{
	"OptionDescriptionBGColor":           prompt.OptionDescriptionBGColor,
	"OptionDescriptionTextColor":         prompt.OptionDescriptionTextColor,
	"OptionInputBGColor":                 prompt.OptionInputBGColor,
	"OptionInputTextColor":               prompt.OptionInputTextColor,
	"OptionPrefixBackgroundColor":        prompt.OptionPrefixBackgroundColor,
	"OptionPrefixTextColor":              prompt.OptionPrefixTextColor,
	"OptionPreviewSuggestionBGColor":     prompt.OptionPreviewSuggestionBGColor,
	"OptionPreviewSuggestionTextColor":   prompt.OptionPreviewSuggestionTextColor,
	"OptionScrollbarBGColor":             prompt.OptionScrollbarBGColor,
	"OptionScrollbarThumbColor":          prompt.OptionScrollbarThumbColor,
	"OptionSelectedDescriptionBGColor":   prompt.OptionSelectedDescriptionBGColor,
	"OptionSelectedDescriptionTextColor": prompt.OptionSelectedDescriptionTextColor,
	"OptionSelectedSuggestionBGColor":    prompt.OptionSelectedSuggestionBGColor,
	"OptionSelectedSuggestionTextColor":  prompt.OptionSelectedSuggestionTextColor,
	"OptionSuggestionBGColor":            prompt.OptionSuggestionBGColor,
	"OptionSuggestionTextColor":          prompt.OptionSuggestionTextColor,
}

var PromptColorNames map[string]prompt.Color = map[string]prompt.Color{
	"DefaultColor": prompt.DefaultColor,
	// Low intensity
	"Black":     prompt.Black,
	"DarkRed":   prompt.DarkRed,
	"DarkGreen": prompt.DarkGreen,
	"Brown":     prompt.Brown,
	"DarkBlue":  prompt.DarkBlue,
	"Purple":    prompt.Purple,
	"Cyan":      prompt.Cyan,
	"LightGrey": prompt.LightGray,
	// High intensity
	"DarkGrey":  prompt.DarkGray,
	"DarkGray":  prompt.DarkGray, // alias used by default config
	"Red":       prompt.Red,
	"Green":     prompt.Green,
	"Yellow":    prompt.Yellow,
	"Blue":      prompt.Blue,
	"Fuchsia":   prompt.Fuchsia,
	"Turquoise": prompt.Turquoise,
	"White":     prompt.White,
}

// DefaultOptions returns the base prompt.Options for the interactive CLI.
func DefaultOptions(exit prompt.ExitChecker) []prompt.Option {
	return []prompt.Option{
		prompt.OptionSetExitCheckerOnInput(exit),
		prompt.OptionPrefix("> "),
		prompt.OptionCompletionOnDown(),
		prompt.OptionShowCompletionAtStart(),
	}
}

// GetColorOptions returns prompt.Options for prompt.New() based on the configured PromptColors.
func GetColorOptions(colors PromptColors) []prompt.Option {
	opts := []prompt.Option{}
	v := reflect.ValueOf(colors)
	t := reflect.TypeOf(colors)

	for i := 0; i < v.NumField(); i++ {
		value := v.Field(i).String()
		field := t.Field(i).Name
		optionName := fmt.Sprintf("Option%s", field)

		colorValue := PromptColorNames[value]
		opts = append(opts, PromptColorFuncs[optionName](colorValue))
	}

	return opts
}

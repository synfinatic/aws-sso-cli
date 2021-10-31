package sso

/*
 * AWS SSO CLI
 * Copyright (c) 2021 Aaron Turner  <synfinatic at gmail dot com>
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
	log "github.com/sirupsen/logrus"
)

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

var DEFAULT_COLOR_CONFIG map[string]interface{} = map[string]interface{}{
	"PromptColors.DescriptionBGColor":           "Turquoise",
	"PromptColors.DescriptionTextColor":         "Black",
	"PromptColors.InputBGColor":                 "DefaultColor",
	"PromptColors.InputTextColor":               "DefaultColor",
	"PromptColors.PrefixBackgroundColor":        "DefaultColor",
	"PromptColors.PrefixTextColor":              "Blue",
	"PromptColors.PreviewSuggestionBGColor":     "DefaultColor",
	"PromptColors.PreviewSuggestionTextColor":   "Green",
	"PromptColors.ScrollbarBGColor":             "Cyan",
	"PromptColors.ScrollbarThumbColor":          "DarkGray",
	"PromptColors.SelectedDescriptionBGColor":   "Cyan",
	"PromptColors.SelectedDescriptionTextColor": "White",
	"PromptColors.SelectedSuggestionBGColor":    "Turquoise",
	"PromptColors.SelectedSuggestionTextColor":  "Black",
	"PromptColors.SuggestionBGColor":            "Cyan",
	"PromptColors.SuggestionTextColor":          "White",
}

type ColorOptionFunction func(prompt.Color) prompt.Option

var PROMPT_COLOR_FUNCS map[string]ColorOptionFunction = map[string]ColorOptionFunction{
	"OptionDescriptionBGColor":           prompt.OptionDescriptionBGColor,
	"OptionDescriptionTextColor":         prompt.OptionInputTextColor,
	"OptionInputBGColor":                 prompt.OptionInputBGColor,
	"OptionInputTextColor":               prompt.OptionInputTextColor,
	"OptionPrefixBackgroundColor":        prompt.OptionPrefixBackgroundColor,
	"OptionPrefixTextColor":              prompt.OptionPrefixTextColor,
	"OptionPreviewSuggestionBGColor":     prompt.OptionPreviewSuggestionBGColor,
	"OptionPreviewSuggestionTextColor":   prompt.OptionPreviewSuggestionTextColor,
	"OptionScrollbarBGColor":             prompt.OptionScrollbarBGColor,
	"OptionScrollbarThumbColor":          prompt.OptionScrollbarThumbColor,
	"OptionSelectedDescriptionBGColor":   prompt.OptionSelectedDescriptionBGColor,
	"OptionSelectedDescriptionTextColor": prompt.OptionSelectedSuggestionTextColor,
	"OptionSelectedSuggestionBGColor":    prompt.OptionSelectedSuggestionBGColor,
	"OptionSelectedSuggestionTextColor":  prompt.OptionSelectedSuggestionTextColor,
	"OptionSuggestionBGColor":            prompt.OptionSuggestionBGColor,
	"OptionSuggestionTextColor":          prompt.OptionSuggestionTextColor,
}

var PROMPT_COLORS map[string]prompt.Color = map[string]prompt.Color{
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
	"Red":       prompt.Red,
	"Green":     prompt.Green,
	"Yellow":    prompt.Yellow,
	"Blue":      prompt.Blue,
	"Fuchsia":   prompt.Fuchsia,
	"Turquoise": prompt.Turquoise,
	"White":     prompt.White,
}

// Our default and common prompt.Options for all CLI interface
func (s *Settings) DefaultOptions(exit prompt.ExitChecker) []prompt.Option {
	return []prompt.Option{
		prompt.OptionSetExitCheckerOnInput(exit),
		prompt.OptionPrefix("> "),
		prompt.OptionCompletionOnDown(),
		prompt.OptionShowCompletionAtStart(),
	}
}

// GetPromptOptions returns a list of promp.Options for prompt.New()
func (s *Settings) GetColorOptions() []prompt.Option {
	opts := []prompt.Option{}
	// Iterate through all the fields in the struct
	v := reflect.ValueOf(s.PromptColors)
	t := reflect.TypeOf(s.PromptColors)

	for i := 0; i < v.NumField(); i++ {
		value := v.Field(i).String()
		field := t.Field(i).Name
		optionName := fmt.Sprintf("Option%s", field)
		log.Debugf("%s => %s", field, value)

		colorValue := PROMPT_COLORS[value]

		opts = append(opts, PROMPT_COLOR_FUNCS[optionName](colorValue))
	}

	return opts
}

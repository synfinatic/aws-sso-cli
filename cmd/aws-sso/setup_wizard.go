package main

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
	"net/http"
	"os"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/manifoldco/promptui"
	"github.com/synfinatic/aws-sso-cli/internal/predictor"
	"github.com/synfinatic/aws-sso-cli/internal/prompt"
	"github.com/synfinatic/aws-sso-cli/internal/uri"
)

const (
	NICE_PROFILE_FORMAT    = "{{ FirstItem .AccountName (.AccountAlias | nospace) }}:{{ .RoleName }}"
	DEFAULT_PROFILE_FORMAT = "{{ .AccountIdPad }}:{{ .RoleName }}"
)

// awsPartition describes an AWS partition relevant to IAM Identity Center setup.
type awsPartition struct {
	Name       string // human-readable label
	Value      string // partition identifier (e.g. "aws", "aws-cn")
	FqdnSuffix string // domain suffix for the SSO start URL hostname
	SSORegions []string
}

var awsPartitions = []awsPartition{
	{
		Name:       "Commercial",
		Value:      "aws",
		FqdnSuffix: ".awsapps.com",
		SSORegions: []string{
			// US
			"us-east-1", "us-east-2", "us-west-1", "us-west-2",

			// Mexico
			"mx-central-1",

			// Africa
			"af-south-1",

			// Israel
			"il-central-1",

			// Asia Pacific
			"ap-east-1", "ap-east-2",
			"ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
			"ap-south-1", "ap-south-2",
			"ap-southeast-1", "ap-southeast-2", "ap-southeast-3",
			"ap-southeast-4", "ap-southeast-5", "ap-southeast-6", "ap-southeast-7",

			// Canada
			"ca-central-1", "ca-west-1",

			// EU
			"eu-central-1", "eu-central-2",
			"eu-west-1", "eu-west-2", "eu-west-3",
			"eu-south-1", "eu-south-2", "eu-north-1",

			// South America
			"sa-east-1",

			// Middle East
			"me-central-1", "me-south-1",
		},
	},
	{
		Name:       "US GovCloud",
		Value:      "aws-us-gov",
		FqdnSuffix: ".signin.amazonaws-us-gov.com",
		SSORegions: []string{"us-gov-east-1", "us-gov-west-1"},
	},
	{
		Name:       "China",
		Value:      "aws-cn",
		FqdnSuffix: ".awsapps.cn",
		SSORegions: []string{"cn-north-1", "cn-northwest-1"},
	},
	// EU doesn't have global endpoints, instead they are region specific
	{
		Name:       "EU Digital Sovereignty (Brandenburg, Germany)",
		Value:      "aws-eusc",
		FqdnSuffix: ".eusc-de-east-1.portal.amazonaws.eu",
		SSORegions: []string{"eusc-de-east-1"},
	},
}

func init() {
	for i := range awsPartitions {
		sort.Strings(awsPartitions[i].SSORegions)
	}
}

func partitionByValue(value string) awsPartition {
	for _, p := range awsPartitions {
		if p.Value == value {
			return p
		}
	}
	return awsPartitions[0] // default to commercial
}

func promptAwsPartition(defaultValue string) awsPartition {
	var i = -1
	var err error

	fmt.Printf("\n")

	items := make([]selectOptions, len(awsPartitions))
	for j, p := range awsPartitions {
		items[j] = selectOptions{Name: p.Name, Value: p.Value}
	}

	label := "AWS Partition:"
	for i < 0 {
		sel := promptui.Select{
			Label:        label,
			Items:        items,
			CursorPos:    defaultSelect(items, defaultValue),
			HideSelected: false,
			Stdout:       &prompt.BellSkipper{},
			Templates:    makeSelectTemplate(label),
		}
		if i, _, err = sel.Run(); err != nil {
			checkSelectError(err)
		}
	}

	return partitionByValue(items[i].Value)
}

type selectOptions struct {
	Name  string
	Value string
}

var yesNoItems = []selectOptions{
	{
		Name:  "No",
		Value: "No",
	},
	{
		Name:  "Yes",
		Value: "Yes",
	},
}

func yesNoPos(val bool) int {
	if val {
		return 1
	}
	return 0
}

func defaultSelect(options []selectOptions, value string) int {
	var i = 0
	for _, v := range options {
		if v.Value == value {
			return i
		}
		i++
	}
	return 0
}

func makeSelectTemplate(label string) *promptui.SelectTemplates {
	return &promptui.SelectTemplates{
		Label:    "{{ . }}",
		Active:   promptui.IconSelect + " {{ .Name | cyan }}",
		Inactive: "  {{ .Name }}",
		Selected: promptui.IconGood + fmt.Sprintf(" %s {{ .Name }}", label),
	}
}

func makePromptTemplate(label string) *promptui.PromptTemplates {
	return &promptui.PromptTemplates{
		Prompt:  "{{ . }}",
		Success: promptui.IconGood + " {{ . }}: ",
	}
}

var ssoNameRegexp *regexp.Regexp

func promptSsoInstance(defaultValue string) string {
	var val string
	var err error

	fmt.Printf("\n")

	// Name our SSO instance
	label := "SSO Instance Name (DefaultSSO)"
	for val == "" {
		prompt := promptui.Prompt{
			Label: label,
			Validate: func(input string) error {
				if ssoNameRegexp == nil {
					ssoNameRegexp, _ = regexp.Compile(`[a-zA-Z0-9-_@:]+`)
				}
				if len(input) > 0 && ssoNameRegexp.Match([]byte(input)) {
					return nil
				}
				return fmt.Errorf("SSO Name must be a valid string")
			},
			Default:   defaultValue,
			Stdout:    &prompt.BellSkipper{},
			Pointer:   promptui.PipeCursor,
			Templates: makePromptTemplate(label),
		}
		if val, err = prompt.Run(); err != nil {
			checkPromptError(err)
		}
	}
	return strings.TrimSpace(val)
}

func checkPromptError(err error) {
	switch err.Error() {
	case "^D":
		// https://github.com/synfinatic/aws-sso-cli/issues/531
		log.Error("sorry, <Del> not supported")
	case "^C":
		log.Fatal("User aborted.")
	default:
		log.Error(err.Error())
	}
}

func checkSelectError(err error) {
	switch err.Error() {
	case "^C":
		log.Fatal("User aborted.")
	default:
		log.Error(err.Error())
	}
}

func promptStartUrl(defaultValue string) string {
	var val string
	var err error
	validURL := false
	var ssoUrlRegexp *regexp.Regexp
	ssoUrlRegexp, _ = regexp.Compile(`https://([a-zA-Z0-9-.]+)/start/?`)

	fmt.Printf("\n")

	for !validURL {
		// Get the hostname of the AWS SSO start URL
		label := "SSO Start URL"
		// Reset cached regexp so it reflects the current partition's suffix
		prompt := promptui.Prompt{
			Label: label,
			Validate: func(input string) error {
				if len(input) > 0 && ssoUrlRegexp.Match([]byte(input)) {
					return nil
				}
				return fmt.Errorf("invalid SSO Start URL: %s", input)
			},
			Default:   defaultValue,
			Stdout:    &prompt.BellSkipper{},
			Pointer:   promptui.PipeCursor,
			Templates: makePromptTemplate(label),
		}
		if val, err = prompt.Run(); err != nil {
			checkPromptError(err)
		}

		defaultValue = strings.TrimSpace(val)

		resp, err := http.Head(defaultValue) // nolint:gosec
		if err != nil {
			log.Error("unable to connect to URL", "url", defaultValue, "error", err.Error())
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			log.Error("URL did not return 200 OK", "url", defaultValue, "status", resp.Status)
			continue
		}
		validURL = true
	}
	return defaultValue
}

func promptAwsSsoRegion(defaultValue string, partition awsPartition) string {
	var i int
	var err error

	fmt.Printf("\n")

	items := []selectOptions{}
	for _, x := range partition.SSORegions {
		items = append(items, selectOptions{
			Value: x,
			Name:  x,
		})
	}

	searcher := func(input string, index int) bool {
		item := items[index]
		name := strings.ReplaceAll(strings.ToLower(item.Name), " ", "")
		input = strings.ReplaceAll(strings.ToLower(input), " ", "")

		return strings.Contains(name, input)
	}

	// Pick our AWS SSO region
	label := "AWS SSO Region (SSORegion):"
	sel := promptui.Select{
		Label:        label,
		Items:        items,
		HideSelected: false,
		CursorPos:    defaultSelect(items, defaultValue),
		Stdout:       &prompt.BellSkipper{},
		Templates:    makeSelectTemplate(label),
		Searcher:     searcher,
	}
	if i, _, err = sel.Run(); err != nil {
		log.Error(err.Error())
	}

	return items[i].Value
}

func promptDefaultRegion(defaultValue string) string {
	var i = -1
	var err error

	fmt.Printf("\n")

	items := []selectOptions{
		{
			Name:  "None",
			Value: "",
		},
	}
	for _, x := range predictor.AvailableAwsRegions {
		items = append(items, selectOptions{
			Value: x,
			Name:  x,
		})
	}

	label := "Default region for connecting to AWS services (DefaultRegion):"
	for i < 0 {
		sel := promptui.Select{
			Label:        label,
			Items:        items,
			CursorPos:    defaultSelect(items, defaultValue),
			HideSelected: false,
			Stdout:       &prompt.BellSkipper{},
			Templates:    makeSelectTemplate(label),
		}
		if i, _, err = sel.Run(); err != nil {
			checkSelectError(err)
		}
	}

	return items[i].Value
}

// promptUseFirefox asks if the user wants to use firefox containers
// and if so, returns the path to the Firefox binary
func promptUseFirefox(defaultValue []string) []string {
	var val string
	var err error

	fmt.Printf("\n")
	if len(defaultValue) == 0 {
		val = ""
	} else {
		val = defaultValue[0]
	}

	label := "Path to Firefox binary (UrlExecCommand)"
	for val == "" {
		prompt := promptui.Prompt{
			Label:     label,
			Stdout:    &prompt.BellSkipper{},
			Default:   firefoxDefaultBrowserPath(val),
			Pointer:   promptui.PipeCursor,
			Validate:  validateBinary,
			Templates: makePromptTemplate(label),
		}
		if val, err = prompt.Run(); err != nil {
			checkPromptError(err)
		}
	}

	val = strings.TrimSpace(val)
	return []string{
		val,
		"%s",
	}
}

func promptUrlAction(defaultValue uri.Action) uri.Action {
	var i = -1
	var err error

	fmt.Printf("\n")

	items := []selectOptions{
		{
			Name:  "Execute custom command",
			Value: "exec",
		},
		{
			Name:  "Print message with URL",
			Value: "print",
		},
		{
			Name:  "Print only the URL",
			Value: "printurl",
		},
	}

	// only valid on localhost
	if !prompt.IsRemoteHost() {
		items = append(items,
			selectOptions{
				Name:  "Copy to clipboard",
				Value: "clip",
			},
			selectOptions{
				Name:  "Open in (default) browser",
				Value: "open",
			},
			selectOptions{
				Name:  "Open in Firefox with Granted Containers plugin",
				Value: "granted-containers",
			},
			selectOptions{
				Name:  "Open in Firefox with Open Url in Container plugin",
				Value: "open-url-in-container",
			},
		)
	}

	dValue := string(defaultValue)

	// How should we deal with URLs?  Note we don't support `exec`
	// here since that is an "advanced" feature
	label := "Default action to take with URLs (UrlAction):"
	for i < 0 {
		sel := promptui.Select{
			Label:     label,
			CursorPos: defaultSelect(items, dValue),
			Items:     items,
			Stdout:    &prompt.BellSkipper{},
			Templates: makeSelectTemplate(label),
		}
		if i, _, err = sel.Run(); err != nil {
			checkSelectError(err)
		}
	}

	action, err := uri.NewAction(items[i].Value)
	if err != nil {
		log.Error(err.Error())
	}
	return action
}

func promptUrlExecCommand(defaultValue []string) []string {
	var val []string
	var err = fmt.Errorf("force one loop")
	var line, command string

	fmt.Printf("\n")

	fmt.Printf("Please enter one per line, the command and list of arguments for UrlExecCommand:\n")

	if len(defaultValue) > 0 {
		command = defaultValue[0]
	}

	for err != nil {
		label := "Binary to execute to open URLs (UrlExecCommand)"
		prompt := promptui.Prompt{
			Label:     label,
			Default:   command,
			Stdout:    &prompt.BellSkipper{},
			Validate:  validateBinary,
			Pointer:   promptui.PipeCursor,
			Templates: makePromptTemplate(label),
		}

		if line, err = prompt.Run(); err != nil {
			checkPromptError(err)
		}
	}

	val = append(val, line)

	// zero out the defaults if we change the command to execute
	if line != command {
		defaultValue = []string{}
	}

	argNum := 1
	for line != "" {
		arg := ""
		if argNum < len(defaultValue) {
			arg = defaultValue[argNum]
		}
		label := fmt.Sprintf("Enter argument #%d or empty string to stop", argNum)
		prompt := promptui.Prompt{
			Label:     label,
			Default:   arg,
			Stdout:    &prompt.BellSkipper{},
			Pointer:   promptui.PipeCursor,
			Templates: makePromptTemplate(label),
		}
		if line, err = prompt.Run(); err != nil {
			checkPromptError(err)
		}
		if line != "" {
			val = append(val, line)
		}
		argNum++
	}
	return val
}

func promptDefaultBrowser(defaultValue string) string {
	var val string
	var err = fmt.Errorf("force loop once")

	fmt.Printf("\n")

	label := "Specify path to browser to use. Leave empty to use system default (Browser)"
	for err != nil {
		prompt := promptui.Prompt{
			Label:     label,
			Default:   defaultValue,
			Stdout:    &prompt.BellSkipper{},
			Pointer:   promptui.PipeCursor,
			Validate:  validateBinaryOrNone,
			Templates: makePromptTemplate(label),
		}

		if val, err = prompt.Run(); err != nil {
			checkPromptError(err)
		} else {
			// need to trim leading/trailing spaces manually
			val = strings.TrimSpace(val)
		}
	}

	return val
}

func promptConsoleDuration(defaultValue int32) int32 {
	var val string
	var err error

	fmt.Printf("\n")

	// https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html
	label := "Minutes before AWS Console sessions expire (ConsoleDuration)"
	for val == "" {
		prompt := promptui.Prompt{
			Label: label,
			Validate: func(input string) error {
				istr := strings.TrimSpace(input)
				x, err := strconv.ParseInt(istr, 10, 64)
				if err != nil || x > 720 || x < 15 {
					return fmt.Errorf("value must be a valid integer between 15 and 720")
				}
				return nil
			},
			Stdout:    &prompt.BellSkipper{},
			Default:   fmt.Sprintf("%d", defaultValue),
			Pointer:   promptui.PipeCursor,
			Templates: makePromptTemplate(label),
		}
		if val, err = prompt.Run(); err != nil {
			checkPromptError(err)
		}
	}

	val = strings.TrimSpace(val)

	x, _ := strconv.ParseInt(val, 10, 32)
	return int32(x) // #nosec
}

func promptHistoryLimit(defaultValue int64) int64 {
	var val string
	var err error

	fmt.Printf("\n")

	label := "Maximum number of History items to keep (HistoryLimit)"
	for val == "" {
		prompt := promptui.Prompt{
			Label:     label,
			Validate:  validateInteger,
			Stdout:    &prompt.BellSkipper{},
			Default:   fmt.Sprintf("%d", defaultValue),
			Pointer:   promptui.PipeCursor,
			Templates: makePromptTemplate(label),
		}
		if val, err = prompt.Run(); err != nil {
			checkPromptError(err)
		}
	}
	val = strings.TrimSpace(val)

	x, _ := strconv.ParseInt(val, 10, 64)
	return x
}

func promptHistoryMinutes(defaultValue int64) int64 {
	var val string
	var err error

	fmt.Printf("\n")

	label := "Number of minutes to keep items in History (HistoryMinutes)"
	for val == "" {
		prompt := promptui.Prompt{
			Label:     label,
			Validate:  validateInteger,
			Default:   fmt.Sprintf("%d", defaultValue),
			Stdout:    &prompt.BellSkipper{},
			Pointer:   promptui.PipeCursor,
			Templates: makePromptTemplate(label),
		}
		if val, err = prompt.Run(); err != nil {
			checkPromptError(err)
		}
	}

	val = strings.TrimSpace(val)

	x, _ := strconv.ParseInt(val, 10, 64)
	return x
}

func promptLogLevel(defaultValue string) string {
	var i = -1
	var err error

	fmt.Printf("\n")

	items := []selectOptions{}
	for _, v := range VALID_LOG_LEVELS {
		items = append(items, selectOptions{
			Name:  v,
			Value: v,
		})
	}

	label := "Log Level (LogLevel):"
	for i < 0 {
		sel := promptui.Select{
			Label:        label,
			Items:        items,
			CursorPos:    index(VALID_LOG_LEVELS, defaultValue),
			HideSelected: false,
			Stdout:       &prompt.BellSkipper{},
			Templates:    makeSelectTemplate(label),
		}
		if i, _, err = sel.Run(); err != nil {
			checkSelectError(err)
		}
	}
	return items[i].Value
}

// index returns the slice index of the value.  Useful for CursorPos
func index(s []string, v string) int {
	for i, x := range s {
		if v == x {
			return i
		}
	}
	return 0
}

func promptAutoConfigCheck(flag bool) bool {
	var i = -1
	var err error

	fmt.Printf("\n")

	label := "Auto update ~/.aws/config with latest AWS SSO roles? (AutoConfigCheck)"
	for i < 0 {
		sel := promptui.Select{
			Label:        label,
			Items:        yesNoItems,
			CursorPos:    yesNoPos(flag),
			HideSelected: false,
			Stdout:       &prompt.BellSkipper{},
			Templates:    makeSelectTemplate(label),
		}
		if i, _, err = sel.Run(); err != nil {
			checkSelectError(err)
		}
	}

	return yesNoItems[i].Value == "Yes"
}

func promptFullTextSearch(flag bool) bool {
	var i = -1
	var err error

	fmt.Printf("\n")

	label := "Enable full-text search? (FullTextSearch)"
	for i < 0 {
		sel := promptui.Select{
			Label:        label,
			Items:        yesNoItems,
			CursorPos:    yesNoPos(flag),
			HideSelected: false,
			Stdout:       &prompt.BellSkipper{},
			Templates:    makeSelectTemplate(label),
		}
		if i, _, err = sel.Run(); err != nil {
			checkSelectError(err)
		}
	}

	return yesNoItems[i].Value == "Yes"
}

func promptProfileFormat(value string) string {
	var err error
	var i = -1

	items := []selectOptions{
		{
			Name:  fmt.Sprintf("Default:\t%s", DEFAULT_PROFILE_FORMAT),
			Value: DEFAULT_PROFILE_FORMAT,
		},
		{
			Name:  fmt.Sprintf("Friendly:\t%s", NICE_PROFILE_FORMAT),
			Value: NICE_PROFILE_FORMAT,
		},
	}

	hasValue := false
	for _, v := range items {
		if v.Value == value {
			hasValue = true
			break
		}
	}
	if !hasValue {
		items = slices.Insert(items, 0, selectOptions{
			Name:  fmt.Sprintf("Custom:\t%s", value),
			Value: value,
		})
	}

	idx := 0
	for i := range items {
		if items[i].Value == value {
			idx = 0
			break
		}
	}

	fmt.Printf("\n")
	label := "ProfileFormat for Profile/$AWS_PROFILE:"
	for i < 0 {
		sel := promptui.Select{
			Label:        label,
			Items:        items,
			CursorPos:    idx,
			HideSelected: false,
			Stdout:       &prompt.BellSkipper{},
			Templates:    makeSelectTemplate(label),
		}
		if i, _, err = sel.Run(); err != nil {
			checkSelectError(err)
		}
	}

	return items[i].Value
}

func promptCacheRefresh(defaultValue int64) int64 {
	var val string
	var err error

	fmt.Printf("\n")

	label := "Hours between AWS SSO cache refresh. 0 to disable. (CacheRefresh)"
	for val == "" {
		prompt := promptui.Prompt{
			Label:     label,
			Validate:  validateInteger,
			Default:   fmt.Sprintf("%d", defaultValue),
			Pointer:   promptui.PipeCursor,
			Templates: makePromptTemplate(label),
		}

		if val, err = prompt.Run(); err != nil {
			checkPromptError(err)
		}
	}
	val = strings.TrimSpace(val)
	x, _ := strconv.ParseInt(val, 10, 64)
	return x
}

func promptConfigProfilesUrlAction(
	defaultValue uri.ConfigProfilesAction, urlAction uri.Action) uri.ConfigProfilesAction {
	var err error
	var i = -1

	fmt.Printf("\n")

	// always valid
	items := []selectOptions{
		{
			Name:  "Copy to clipboard",
			Value: "clip",
		},
		{
			Name:  "Open in (default) browser",
			Value: "open",
		},
	}

	if defaultValue == uri.ConfigProfilesUndef {
		defaultValue, _ = uri.NewConfigProfilesAction(string(urlAction))
	}

	// if UrlExecCommand uses firefox, then we need to be consitent
	if urlAction.IsContainer() {
		items = append(items, selectOptions{
			Name:  "Open in Firefox with Granted Containers plugin",
			Value: "granted-containers",
		})

		items = append(items, selectOptions{
			Name:  "Open in Firefox with Open Url in Container plugin",
			Value: "open-url-in-container",
		})
	} else {
		items = append(items, selectOptions{
			Name:  "Execute custom command",
			Value: "exec",
		})
	}

	dValue := string(defaultValue)

	label := "How to open URLs via $AWS_PROFILE? (ConfigProfilesUrlAction)"
	for i < 0 {
		sel := promptui.Select{
			Label:        label,
			Items:        items,
			CursorPos:    defaultSelect(items, dValue),
			HideSelected: false,
			Stdout:       &prompt.BellSkipper{},
			Templates:    makeSelectTemplate(label),
		}

		if i, _, err = sel.Run(); err != nil {
			checkSelectError(err)
		}
	}

	ret, _ := uri.NewConfigProfilesAction(items[i].Value)
	return ret
}

func validateInteger(input string) error {
	input = strings.TrimSpace(input)
	_, err := strconv.ParseInt(input, 10, 64)
	if err != nil {
		return fmt.Errorf("value must be a valid integer")
	}
	return nil
}

// validateBinary ensures the input is a valid binary on the system
func validateBinary(input string) error {
	input = strings.TrimSpace(input)
	s, err := os.Stat(input)
	if err != nil {
		return err
	}
	switch runtime.GOOS {
	case "windows":
		// Windows doesn't have file permissions
		if s.Mode().IsRegular() {
			return nil
		}
	default:
		// must be a file and user execute bit set
		if s.Mode().IsRegular() && s.Mode().Perm()&0100 > 0 {
			return nil
		}
	}
	return fmt.Errorf("not a valid valid")
}

// validateBinaryOrNone is just like validateBinary(), but we accept
// an empty string
func validateBinaryOrNone(input string) error {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}

	s, err := os.Stat(input)
	if err != nil {
		return err
	}
	switch runtime.GOOS {
	case "windows":
		// Windows doesn't have file permissions
		if s.Mode().IsRegular() {
			return nil
		}
	default:
		// must be a file and user execute bit set
		if s.Mode().IsRegular() && s.Mode().Perm()&0100 > 0 {
			return nil
		}
	}
	return fmt.Errorf("not a valid valid")
}

// returns the default path to the firefox browser
func firefoxDefaultBrowserPath(path string) string {
	if len(path) != 0 {
		return path
	}

	switch runtime.GOOS {
	case "darwin":
		path = "/Applications/Firefox.app/Contents/MacOS/firefox"
	case "linux":
		path = "/usr/bin/firefox"
	case "windows":
		path = "\\Program Files\\Mozilla Firefox\\firefox.exe"
	default:
	}
	return path
}

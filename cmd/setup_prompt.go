package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2022 Aaron Turner  <synfinatic at gmail dot com>
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
	"net"
	"os"
	"regexp"
	"runtime"
	"strconv"

	"github.com/manifoldco/promptui"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
)

const (
	START_URL_FORMAT  = "https://%s.awsapps.com/start"
	START_FQDN_FORMAT = "%s.awsapps.com"
)

// https://docs.aws.amazon.com/general/latest/gr/sso.html
var AvailableAwsSSORegions []string = []string{
	"us-east-1",
	"us-east-2",
	"us-west-2",
	"ap-south-1",
	"ap-northeast-2",
	"ap-southeast-1",
	"ap-southeast-2",
	"ap-northeast-1",
	"ca-central-1",
	"eu-central-1",
	"eu-west-1",
	"eu-west-2",
	"eu-west-3",
	"eu-north-1",
	"sa-east-1",
	"us-gov-west-1",
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
	var i int = 0
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
	prompt := promptui.Prompt{
		Label: label,
		Validate: func(input string) error {
			if ssoNameRegexp == nil {
				ssoNameRegexp, _ = regexp.Compile(`^[a-zA-Z0-9-_@:]+$`)
			}
			if len(input) > 0 && ssoNameRegexp.Match([]byte(input)) {
				return nil
			}
			return fmt.Errorf("SSO Name must be a valid string")
		},
		Default:   defaultValue,
		Pointer:   promptui.PipeCursor,
		Templates: makePromptTemplate(label),
	}
	if val, err = prompt.Run(); err != nil {
		log.Fatal(err)
	}
	return val
}

var ssoHostnameRegexp *regexp.Regexp

func promptStartUrl(defaultValue string) string {
	var val string
	var err error
	validFQDN := false

	fmt.Printf("\n")

	for !validFQDN {
		// Get the hostname of the AWS SSO start URL
		label := "SSO Start URL Hostname (XXXXXXX.awsapps.com)"
		prompt := promptui.Prompt{
			Label: label,
			Validate: func(input string) error {
				if ssoHostnameRegexp == nil {
					ssoHostnameRegexp, _ = regexp.Compile(`^([a-zA-Z0-9-]+)(\.awsapps\.com)?$`)
				}
				if len(input) > 0 && len(input) < 64 && ssoHostnameRegexp.Match([]byte(input)) {
					return nil
				}
				return fmt.Errorf("Invalid DNS hostname: %s", input)
			},
			Default:   defaultValue,
			Pointer:   promptui.PipeCursor,
			Templates: makePromptTemplate(label),
		}
		if val, err = prompt.Run(); err != nil {
			log.Fatal(err)
		}

		if _, err := net.LookupHost(fmt.Sprintf(START_FQDN_FORMAT, val)); err == nil {
			validFQDN = true
		} else if err != nil {
			log.Errorf("Unable to resolve %s", fmt.Sprintf(START_FQDN_FORMAT, val))
		}
	}

	return val
}

func promptAwsSsoRegion(defaultValue string) string {
	var i int
	var err error

	fmt.Printf("\n")

	items := []selectOptions{}
	for _, x := range AvailableAwsSSORegions {
		items = append(items, selectOptions{
			Value: x,
			Name:  x,
		})
	}

	// Pick our AWS SSO region
	label := "AWS SSO Region (SSORegion):"
	sel := promptui.Select{
		Label:        label,
		Items:        items,
		HideSelected: false,
		CursorPos:    defaultSelect(items, defaultValue),
		Stdout:       &utils.BellSkipper{},
		Templates:    makeSelectTemplate(label),
	}
	if i, _, err = sel.Run(); err != nil {
		log.Fatal(err)
	}

	return items[i].Value
}

func promptDefaultRegion(defaultValue string) string {
	var i int
	var err error

	fmt.Printf("\n")

	items := []selectOptions{
		{
			Name:  "None",
			Value: "",
		},
	}
	for _, x := range AvailableAwsRegions {
		items = append(items, selectOptions{
			Value: x,
			Name:  x,
		})
	}

	label := "Default region for connecting to AWS services (DefaultRegion):"
	sel := promptui.Select{
		Label:        label,
		Items:        items,
		CursorPos:    defaultSelect(items, defaultValue),
		HideSelected: false,
		Stdout:       &utils.BellSkipper{},
		Templates:    makeSelectTemplate(label),
	}
	if i, _, err = sel.Run(); err != nil {
		log.Fatal(err)
	}

	return items[i].Value
}

// promptUseFirefox asks if the user wants to use firefox containers
// and if so, returns the path to the Firefox binary
func promptUseFirefox(defaultValue string) string {
	var val string
	var i int
	var err error

	fmt.Printf("\n")

	label := "Use Firefox containers to open URLs?"
	sel := promptui.Select{
		Label:        label,
		HideSelected: false,
		Items:        yesNoItems,
		CursorPos:    yesNoPos(defaultValue != ""),
		Stdout:       &utils.BellSkipper{},
		Templates:    makeSelectTemplate(label),
	}
	if i, _, err = sel.Run(); err != nil {
		log.Fatal(err)
	}

	if yesNoItems[i].Value == "No" {
		return ""
	}

	fmt.Printf("\n")

	fmt.Printf("Ensure that you have the 'Open external links in a container' plugin for Firefox.")
	label = "Path to Firefox binary"
	prompt := promptui.Prompt{
		Label:     label,
		Stdout:    &utils.BellSkipper{},
		Default:   firefoxDefaultBrowserPath(defaultValue),
		Pointer:   promptui.PipeCursor,
		Validate:  validateBinary,
		Templates: makePromptTemplate(label),
	}
	if val, err = prompt.Run(); err != nil {
		log.Fatal(err)
	}

	return val
}

func promptUrlAction(defaultValue string, useFirefox bool) string {
	var i int
	var err error

	cmd := "Execute custom command"
	if useFirefox {
		cmd = "Open in Firefox"
	}
	fmt.Printf("\n")

	items := []selectOptions{
		{
			Name:  "Copy to clipboard",
			Value: "clip",
		},
		{
			Name:  cmd,
			Value: "exec",
		},
		{
			Name:  "Open in (default) browser",
			Value: "open",
		},
		{
			Name:  "Print message with URL",
			Value: "print",
		},
		{
			Name:  "Print just the URL",
			Value: "printurl",
		},
	}

	// How should we deal with URLs?  Note we don't support `exec`
	// here since that is an "advanced" feature
	label := "Default action to take with URLs (UrlAction):"
	sel := promptui.Select{
		Label:     label,
		CursorPos: defaultSelect(items, defaultValue),
		Items:     items,
		Stdout:    &utils.BellSkipper{},
		Templates: makeSelectTemplate(label),
	}
	if i, _, err = sel.Run(); err != nil {
		log.Fatal(err)
	}

	return items[i].Value
}

func promptUrlExecCommand(defaultValue []interface{}) []interface{} {
	var val []interface{}
	var err error
	var line string
	argNum := 1

	fmt.Printf("\n")

	fmt.Printf("Please enter one per line, the command and list of arguments for UrlExecCommand:\n")

	command := defaultValue[0].(string)
	label := "Binary to execute to open URLs"
	prompt := promptui.Prompt{
		Label:     label,
		Default:   command,
		Stdout:    &utils.BellSkipper{},
		Validate:  validateBinary,
		Pointer:   promptui.PipeCursor,
		Templates: makePromptTemplate(label),
	}

	if line, err = prompt.Run(); err != nil {
		log.Fatal(err)
	}

	val = append(val, interface{}(line))

	// zero out the defaults if we change the command to execute
	if line != defaultValue[0] {
		defaultValue = []interface{}{}
	}

	for line != "" {
		arg := ""
		if argNum < len(defaultValue) {
			arg = defaultValue[argNum].(string)
		}
		label := fmt.Sprintf("Enter argument #%d or empty string to stop", argNum)
		prompt = promptui.Prompt{
			Label:     label,
			Default:   arg,
			Stdout:    &utils.BellSkipper{},
			Pointer:   promptui.PipeCursor,
			Templates: makePromptTemplate(label),
		}
		if line, err = prompt.Run(); err != nil {
			log.Fatal(err)
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
	var err error

	fmt.Printf("\n")

	label := "Specify path to browser to use. Leave empty to use system default (Browser)"
	prompt := promptui.Prompt{
		Label:     label,
		Default:   defaultValue,
		Stdout:    &utils.BellSkipper{},
		Pointer:   promptui.PipeCursor,
		Validate:  validateBinaryOrNone,
		Templates: makePromptTemplate(label),
	}

	if val, err = prompt.Run(); err != nil {
		log.Fatal(err)
	}

	return val
}

func promptConsoleDuration(defaultValue int32) int32 {
	var val string
	var err error

	fmt.Printf("\n")

	// https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html
	label := "Minutes before AWS Console sessions expire (ConsoleDuration)"
	prompt := promptui.Prompt{
		Label: label,
		Validate: func(input string) error {
			x, err := strconv.ParseInt(input, 10, 64)
			if err != nil || x > 2160 || x < 15 {
				return fmt.Errorf("Value must be a valid integer between 15 and 2160")
			}
			return nil
		},
		Stdout:    &utils.BellSkipper{},
		Default:   fmt.Sprintf("%d", defaultValue),
		Pointer:   promptui.PipeCursor,
		Templates: makePromptTemplate(label),
	}
	if val, err = prompt.Run(); err != nil {
		log.Fatal(err)
	}

	x, _ := strconv.ParseInt(val, 10, 32)
	return int32(x)
}

func promptHistoryLimit(defaultValue int64) int64 {
	var val string
	var err error

	fmt.Printf("\n")

	label := "Maximum number of History items to keep (HistoryLimit)"
	prompt := promptui.Prompt{
		Label:     label,
		Validate:  validateInteger,
		Stdout:    &utils.BellSkipper{},
		Default:   fmt.Sprintf("%d", defaultValue),
		Pointer:   promptui.PipeCursor,
		Templates: makePromptTemplate(label),
	}
	if val, err = prompt.Run(); err != nil {
		log.Fatal(err)
	}

	x, _ := strconv.ParseInt(val, 10, 64)
	return x
}

func promptHistoryMinutes(defaultValue int64) int64 {
	var val string
	var err error

	fmt.Printf("\n")

	label := "Number of minutes to keep items in History (HistoryMinutes)"
	prompt := promptui.Prompt{
		Label:     label,
		Validate:  validateInteger,
		Default:   fmt.Sprintf("%d", defaultValue),
		Stdout:    &utils.BellSkipper{},
		Pointer:   promptui.PipeCursor,
		Templates: makePromptTemplate(label),
	}
	if val, err = prompt.Run(); err != nil {
		log.Fatal(err)
	}

	x, _ := strconv.ParseInt(val, 10, 64)
	return x
}

func promptLogLevel(defaultValue string) string {
	var i int
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
	sel := promptui.Select{
		Label:        label,
		Items:        items,
		CursorPos:    index(VALID_LOG_LEVELS, defaultValue),
		HideSelected: false,
		Stdout:       &utils.BellSkipper{},
		Templates:    makeSelectTemplate(label),
	}
	if i, _, err = sel.Run(); err != nil {
		log.Fatal(err)
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
	var i int
	var err error

	fmt.Printf("\n")

	label := "Auto update ~/.aws/config with latest AWS SSO roles? (AutoConfigCheck)"
	sel := promptui.Select{
		Label:        label,
		Items:        yesNoItems,
		CursorPos:    yesNoPos(flag),
		HideSelected: false,
		Stdout:       &utils.BellSkipper{},
		Templates:    makeSelectTemplate(label),
	}
	if i, _, err = sel.Run(); err != nil {
		log.WithError(err).Fatalf("Unable to select AutoConfigCheck")
	}

	return yesNoItems[i].Value == "Yes"
}

func promptCacheRefresh(defaultValue int64) int64 {
	var val string
	var err error

	fmt.Printf("\n")

	label := "Hours between AWS SSO cache refresh. 0 to disable. (CacheRefresh)"
	prompt := promptui.Prompt{
		Label:     label,
		Validate:  validateInteger,
		Default:   fmt.Sprintf("%d", defaultValue),
		Pointer:   promptui.PipeCursor,
		Templates: makePromptTemplate(label),
	}

	if val, err = prompt.Run(); err != nil {
		log.Fatal(err)
	}
	x, _ := strconv.ParseInt(val, 10, 64)
	return x
}

func promptConfigProfilesUrlAction(defaultValue string, useFirefox bool) string {
	var err error
	var i int

	fmt.Printf("\n")

	cmd := "Execute custom command"
	if useFirefox {
		cmd = "Open in Firefox"
	}

	// Must specify these in same order as CONFIG_OPEN_OPTIONS
	items := []selectOptions{
		{
			Name:  "Copy to clipboard",
			Value: "clip",
		},
		{
			Name:  cmd,
			Value: "exec",
		},
		{
			Name:  "Open URL in (default) browser",
			Value: "open",
		},
	}

	label := "How to open URLs via $AWS_PROFILE? (ConfigProfilesUrlAction)"

	sel := promptui.Select{
		Label:        label,
		Items:        items,
		CursorPos:    index(CONFIG_OPEN_OPTIONS, defaultValue),
		HideSelected: false,
		Stdout:       &utils.BellSkipper{},
		Templates:    makeSelectTemplate(label),
	}

	if i, _, err = sel.Run(); err != nil {
		log.Fatal(err)
	}

	return items[i].Value
}

func validateInteger(input string) error {
	_, err := strconv.ParseInt(input, 10, 64)
	if err != nil {
		return fmt.Errorf("Value must be a valid integer")
	}
	return nil
}

// validateBinary ensures the input is a valid binary on the system
func validateBinary(input string) error {
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

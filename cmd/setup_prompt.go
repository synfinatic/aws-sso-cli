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

func promptSsoInstance(defaultValue string) (string, error) {
	var val string
	var err error

	// Name our SSO instance
	prompt := promptui.Prompt{
		Label:    "SSO Instance Name (DefaultSSO)",
		Validate: validateSSOName,
		Default:  defaultValue,
		Pointer:  promptui.PipeCursor,
	}
	if val, err = prompt.Run(); err != nil {
		return "", err
	}
	return val, nil
}

func promptStartUrl(defaultValue string) (string, error) {
	var val string
	var err error
	validFQDN := false

	for !validFQDN {
		// Get the hostname of the AWS SSO start URL
		prompt := promptui.Prompt{
			Label:    "SSO Start URL Hostname (XXXXXXX.awsapps.com)",
			Validate: validateSSOHostname,
			Default:  defaultValue,
			Pointer:  promptui.PipeCursor,
		}
		if val, err = prompt.Run(); err != nil {
			return "", err
		}

		if _, err := net.LookupHost(fmt.Sprintf(START_FQDN_FORMAT, val)); err == nil {
			validFQDN = true
		} else if err != nil {
			log.Errorf("Unable to resolve %s", fmt.Sprintf(START_FQDN_FORMAT, val))
		}
	}

	return val, nil
}

func promptAwsSsoRegion(defaultValue string) (string, error) {
	var val string
	var err error

	pos := 0
	for i, v := range AvailableAwsSSORegions {
		if v == defaultValue {
			pos = i
		}
	}

	// Pick our AWS SSO region
	label := "AWS SSO Region (SSORegion)"
	sel := promptui.Select{
		Label:        label,
		Items:        AvailableAwsSSORegions,
		HideSelected: false,
		CursorPos:    pos,
		Stdout:       &utils.BellSkipper{},
		Templates: &promptui.SelectTemplates{
			Selected: fmt.Sprintf(`%s: {{ . | faint }}`, label),
		},
	}
	if _, val, err = sel.Run(); err != nil {
		return "", err
	}

	return val, nil
}

func promptCacheRefresh(defaultValue int64) (int64, error) {
	var val string
	var err error

	prompt := promptui.Prompt{
		Label:    "Number of hours between refreshing AWS SSO cache (0 to disable)",
		Validate: validateInteger,
		Default:  fmt.Sprintf("%d", defaultValue),
		Pointer:  promptui.PipeCursor,
	}
	if val, err = prompt.Run(); err != nil {
		return 0, err
	}
	return strconv.ParseInt(val, 10, 64)
}

func promptDefaultRegion(defaultValue string) (string, error) {
	var val string
	var err error

	// Pick the default AWS region to use
	defaultRegions := []string{"None"}
	defaultRegions = append(defaultRegions, AvailableAwsRegions...)

	for _, v := range defaultRegions {
		if v == defaultValue {
			return v, nil
		}
	}

	label := "Default region for connecting to AWS (DefaultRegion)"
	sel := promptui.Select{
		Label:        label,
		Items:        defaultRegions,
		HideSelected: false,
		Stdout:       &utils.BellSkipper{},
		Templates: &promptui.SelectTemplates{
			Selected: fmt.Sprintf(`%s: {{ . | faint }}`, label),
		},
	}
	if _, val, err = sel.Run(); err != nil {
		return "", err
	}

	if val == "None" {
		val = ""
	}

	return val, nil
}

func promptUseFirefox(defaultValue string) (string, error) {
	var val, useFirefox string
	var err error

	label := "Use Firefox containers to open URLs?"
	sel := promptui.Select{
		Label:        label,
		HideSelected: false,
		Items:        []string{"Yes", "No"},
		Stdout:       &utils.BellSkipper{},
		Templates: &promptui.SelectTemplates{
			Selected: fmt.Sprintf(`%s: {{ . | faint }}`, label),
		},
	}
	if _, useFirefox, err = sel.Run(); err != nil {
		return "", err
	}

	if useFirefox == "Yes" {
		fmt.Printf("Ensure that you have the 'Open external links in a container' plugin for Firefox.")
		prompt := promptui.Prompt{
			Label:    "Path to Firefox binary",
			Stdout:   &utils.BellSkipper{},
			Default:  firefoxDefaultBrowserPath(defaultValue),
			Pointer:  promptui.PipeCursor,
			Validate: validateBinary,
		}
		if val, err = prompt.Run(); err != nil {
			return "", err
		}
	}

	return val, nil
}

func promptUrlAction() (string, error) {
	var val string
	var err error

	// How should we deal with URLs?  Note we don't support `exec`
	// here since that is an "advanced" feature
	label := "Default action to take with URLs (UrlAction)"
	sel := promptui.Select{
		Label:  label,
		Items:  []string{"open", "print", "printurl", "clip"},
		Stdout: &utils.BellSkipper{},
		Templates: &promptui.SelectTemplates{
			Selected: fmt.Sprintf(`%s: {{ . | faint }}`, label),
		},
	}
	if _, val, err = sel.Run(); err != nil {
		return "", err
	}

	return val, nil
}

func promptDefaultBrowser(defaultValue string) (string, error) {
	var val string
	var err error
	override := ""

	label := "Override default browser?"
	sel := promptui.Select{
		Label:  label,
		Items:  []string{"No", "Yes"},
		Stdout: &utils.BellSkipper{},
		Templates: &promptui.SelectTemplates{
			Selected: fmt.Sprintf(`%s: {{ . | faint }}`, label),
		},
	}
	if _, override, err = sel.Run(); err != nil {
		return "", err
	}

	if override == "No" {
		return "", nil
	}

	prompt := promptui.Prompt{
		Label:    "Specify path to browser to use",
		Default:  defaultValue,
		Stdout:   &utils.BellSkipper{},
		Pointer:  promptui.PipeCursor,
		Validate: validateBinary,
	}
	if val, err = prompt.Run(); err != nil {
		return "", err
	}

	return val, nil
}

func promptHistoryLimit(defaultValue int64) (int64, error) {
	var limit string
	var err error

	prompt := promptui.Prompt{
		Label:    "Maximum number of History items to keep (HistoryLimit)",
		Validate: validateInteger,
		Default:  fmt.Sprintf("%d", defaultValue),
		Pointer:  promptui.PipeCursor,
	}
	if limit, err = prompt.Run(); err != nil {
		return 0, err
	}
	return strconv.ParseInt(limit, 10, 64)
}

func promptHistoryMinutes(defaultValue int64) (int64, error) {
	var err error
	var minutes string

	if defaultValue >= 0 {
		return defaultValue, nil
	}

	prompt := promptui.Prompt{
		Label:    "Number of minutes to keep items in History (HistoryMinutes)",
		Validate: validateInteger,
		Default:  "1440",
		Pointer:  promptui.PipeCursor,
	}
	if minutes, err = prompt.Run(); err != nil {
		return 0, err
	}
	return strconv.ParseInt(minutes, 10, 64)
}

func promptLogLevel(defaultValue string) (string, error) {
	var val string
	var err error

	logLevels := []string{
		"error",
		"warn",
		"info",
		"debug",
		"trace",
	}

	if defaultValue != "" && utils.StrListContains(defaultValue, logLevels) {
		return defaultValue, nil
	}

	label := "Log Level (LogLevel)"
	sel := promptui.Select{
		Label:        label,
		Items:        logLevels,
		HideSelected: false,
		CursorPos:    1, // warn
		Stdout:       &utils.BellSkipper{},
		Templates: &promptui.SelectTemplates{
			Selected: fmt.Sprintf(`%s: {{ . | faint }}`, label),
		},
	}
	if _, val, err = sel.Run(); err != nil {
		return "", err
	}
	return val, nil
}

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

func promptAutoConfigCheck(flag bool, action string) (bool, string, error) {
	var val string
	var err error

	label := fmt.Sprintf("Auto update %s (AutoConfigCheck)", utils.GetHomePath("~/.aws.config"))
	sel := promptui.Select{
		Label:        label,
		Items:        []string{"Yes", "No"},
		HideSelected: false,
		Stdout:       &utils.BellSkipper{},
		Templates: &promptui.SelectTemplates{
			Selected: fmt.Sprintf(`%s: {{ . | faint }}`, label),
		},
	}
	if _, val, err = sel.Run(); err != nil {
		return false, "", err
	}

	if val == "No" {
		return false, "", nil
	}

	label = "How to open URLs via $AWS_PROFILE (ConfigUrlAction)"
	sel = promptui.Select{
		Label:        label,
		Items:        VALID_CONFIG_OPEN,
		HideSelected: false,
		Stdout:       &utils.BellSkipper{},
		Templates: &promptui.SelectTemplates{
			Selected: fmt.Sprintf(`%s: {{ . | faint }}`, label),
		},
	}

	if _, val, err = sel.Run(); err != nil {
		return false, "", err
	}

	return true, val, nil
}

var ssoHostnameRegexp *regexp.Regexp

// validateSSOHostname verifies our SSO Start url is in the format of http://xxxxx.awsapps.com/start
// and the FQDN is valid
func validateSSOHostname(input string) error {
	if ssoHostnameRegexp == nil {
		ssoHostnameRegexp, _ = regexp.Compile(`^([a-zA-Z0-9-]+)(\.awsapps\.com)?$`)
	}
	if len(input) > 0 && len(input) < 64 && ssoHostnameRegexp.Match([]byte(input)) {
		return nil
	}
	return fmt.Errorf("Invalid DNS hostname: %s", input)
}

var ssoNameRegexp *regexp.Regexp

// validateSSOName just makes sure we have some text
func validateSSOName(input string) error {
	if ssoNameRegexp == nil {
		ssoNameRegexp, _ = regexp.Compile(`^[a-zA-Z0-9]+$`)
	}
	if len(input) > 0 && ssoNameRegexp.Match([]byte(input)) {
		return nil
	}
	return fmt.Errorf("SSO Name must be a valid string")
}

func validateInteger(input string) error {
	_, err := strconv.ParseInt(input, 10, 64)
	if err != nil {
		return fmt.Errorf("Value must be a valid integer")
	}
	return nil
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

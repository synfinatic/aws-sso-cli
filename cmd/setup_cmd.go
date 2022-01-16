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
	"regexp"
	"strconv"
	"strings"

	"github.com/manifoldco/promptui"
	log "github.com/sirupsen/logrus"
	"github.com/synfinatic/aws-sso-cli/sso"
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

const (
	START_URL_FORMAT  = "https://%s.awsapps.com/start"
	START_FQDN_FORMAT = "%s.awsapps.com"
)

// SetupCmd defines the Kong args for the setup command (which currently doesn't exist)
type SetupCmd struct {
	DefaultRegion    string `kong:"help='Default AWS region for running commands (or \"None\")'"`
	UrlAction        string `kong:"name='default-url-action',help='How to handle URLs [open|print|clip]'"`
	SSOStartHostname string `kong:"help='AWS SSO User Portal Hostname'"`
	SSORegion        string `kong:"help='AWS SSO Instance Region'"`
	HistoryLimit     int64  `kong:"help='Number of items to keep in History',default=-1"`
	HistoryMinutes   int64  `kong:"help='Number of minutes to keep items in History',default=-1"`
	DefaultLevel     string `kong:"help='Logging level [error|warn|info|debug|trace]'"`
	Force            bool   `kong:"help='Force override of existing config file'"`
}

// Run executes the setup command
func (cc *SetupCmd) Run(ctx *RunContext) error {
	return setupWizard(ctx)
}

func setupWizard(ctx *RunContext) error {
	var err error
	var instanceName, startHostname, ssoRegion, awsRegion, urlAction string
	var historyLimit, historyMinutes, logLevel string
	var hLimit, hMinutes int64

	if ctx.Cli.Setup.UrlAction != "" {
		if err := urlActionValidate(ctx.Cli.Setup.UrlAction); err != nil {
			log.Fatalf("Invalid value for --default-url-action %s", ctx.Cli.Setup.UrlAction)
		}
	}

	if ctx.Cli.Setup.DefaultLevel != "" {
		if err := logLevelValidate(ctx.Cli.Setup.DefaultLevel); err != nil {
			log.Fatalf("Invalid value for --default-level %s", ctx.Cli.Setup.DefaultLevel)
		}
	}

	// Name our SSO instance
	prompt := promptui.Prompt{
		Label:    "SSO Instance Name (DefaultSSO)",
		Validate: validateSSOName,
		Default:  ctx.Cli.SSO,
		Pointer:  promptui.PipeCursor,
	}
	if instanceName, err = prompt.Run(); err != nil {
		return err
	}

	validFQDN := false
	for !validFQDN {
		// Get the hostname of the AWS SSO start URL
		prompt = promptui.Prompt{
			Label:    "SSO Start URL Hostname (XXXXXXX.awsapps.com)",
			Validate: validateSSOHostname,
			Default:  ctx.Cli.Setup.SSOStartHostname,
			Pointer:  promptui.PipeCursor,
		}
		if startHostname, err = prompt.Run(); err != nil {
			return err
		}
		if strings.HasSuffix(startHostname, ".awsapps.com") {
			fqdn := strings.Split(startHostname, ".")
			startHostname = fqdn[0]
		}
		if _, err := net.LookupHost(fmt.Sprintf(START_FQDN_FORMAT, startHostname)); err == nil {
			validFQDN = true
		} else if err != nil {
			log.Errorf("Unable to resolve %s", fmt.Sprintf(START_FQDN_FORMAT, startHostname))
		}
	}

	// Pick our AWS SSO region
	label := "AWS SSO Region (SSORegion)"
	sel := promptui.Select{
		Label:        label,
		Items:        AvailableAwsSSORegions,
		HideSelected: false,
		Stdout:       &bellSkipper{},
		Templates: &promptui.SelectTemplates{
			Selected: fmt.Sprintf(`%s: {{ . | faint }}`, label),
		},
	}
	if _, ssoRegion, err = sel.Run(); err != nil {
		return err
	}

	// Pick the default AWS region to use
	defaultRegions := []string{"None"}
	defaultRegions = append(defaultRegions, AvailableAwsRegions...)

	for _, v := range defaultRegions {
		if v == ctx.Cli.Setup.DefaultRegion {
			awsRegion = v
			break
		}
	}

	if len(awsRegion) == 0 {
		label = "Default region for connecting to AWS (DefaultRegion)"
		sel = promptui.Select{
			Label:        label,
			Items:        defaultRegions,
			HideSelected: false,
			Stdout:       &bellSkipper{},
			Templates: &promptui.SelectTemplates{
				Selected: fmt.Sprintf(`%s: {{ . | faint }}`, label),
			},
		}
		if _, awsRegion, err = sel.Run(); err != nil {
			return err
		}
	}

	if awsRegion == "None" {
		awsRegion = ""
	}

	// UrlAction
	if len(ctx.Cli.Setup.UrlAction) > 0 {
		if err := urlActionValidate(ctx.Cli.Setup.UrlAction); err == nil {
			urlAction = ctx.Cli.Setup.UrlAction
		}
	}

	if len(urlAction) == 0 {
		// How should we deal with URLs?
		label = "Default action to take with URLs (UrlAction)"
		sel = promptui.Select{
			Label:  label,
			Items:  []string{"open", "print", "clip"},
			Stdout: &bellSkipper{},
			Templates: &promptui.SelectTemplates{
				Selected: fmt.Sprintf(`%s: {{ . | faint }}`, label),
			},
		}
		if _, urlAction, err = sel.Run(); err != nil {
			return err
		}
	}

	// HistoryLimit
	if ctx.Cli.Setup.HistoryLimit < 0 {
		prompt = promptui.Prompt{
			Label:    "Maximum number of History items to keep (HistoryLimit)",
			Validate: validateInteger,
			Default:  "10",
			Pointer:  promptui.PipeCursor,
		}
		if historyLimit, err = prompt.Run(); err != nil {
			return err
		}
		hLimit, _ = strconv.ParseInt(historyLimit, 10, 64)
	} else {
		hLimit = ctx.Cli.Setup.HistoryLimit
	}

	// HistoryMinutes
	if ctx.Cli.Setup.HistoryMinutes < 0 {
		prompt = promptui.Prompt{
			Label:    "Number of minutes to keep items in History (HistoryMinutes)",
			Validate: validateInteger,
			Default:  "1440",
			Pointer:  promptui.PipeCursor,
		}
		if historyMinutes, err = prompt.Run(); err != nil {
			return err
		}
		hMinutes, _ = strconv.ParseInt(historyMinutes, 10, 64)
	} else {
		hMinutes = ctx.Cli.Setup.HistoryMinutes
	}

	// LogLevel
	if ctx.Cli.Setup.DefaultLevel == "" {
		logLevels := []string{
			"error",
			"warn",
			"info",
			"debug",
			"trace",
		}
		label = "Log Level (LogLevel)"
		sel = promptui.Select{
			Label:        label,
			Items:        logLevels,
			HideSelected: false,
			CursorPos:    1, // warn
			Stdout:       &bellSkipper{},
			Templates: &promptui.SelectTemplates{
				Selected: fmt.Sprintf(`%s: {{ . | faint }}`, label),
			},
		}
		if _, logLevel, err = sel.Run(); err != nil {
			return err
		}
	} else {
		logLevel = ctx.Cli.Setup.DefaultLevel
	}

	// write config file
	s := sso.Settings{
		DefaultSSO:     instanceName,
		SSO:            map[string]*sso.SSOConfig{},
		UrlAction:      urlAction,
		HistoryLimit:   hLimit,
		HistoryMinutes: hMinutes,
		LogLevel:       logLevel,
	}
	s.SSO[instanceName] = &sso.SSOConfig{
		SSORegion:     ssoRegion,
		StartUrl:      fmt.Sprintf(START_URL_FORMAT, startHostname),
		DefaultRegion: awsRegion,
	}
	return s.Save(ctx.Cli.ConfigFile, false)
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

package main

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
	"net"
	"net/url"
	"strings"

	"github.com/manifoldco/promptui"
	// log "github.com/sirupsen/logrus"
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

// SetupCmd defines the Kong args for the setup command (which currently doesn't exist)
type SetupCmd struct {
	DefaultRegion string `kong:"help='Default AWS region for running commands (or \"None\")'"`
	UrlAction     string `kong:"name='default-url-action',help='How to handle URLs [open|print|clip]'"`
	SSOStartUrl   string `kong:"help='AWS SSO User Portal URL'"`
	SSORegion     string `kong:"help='AWS SSO Instance Region'"`
	Force         bool   `kong:"help='Force override of existing config file'"`
}

// Run executes the setup command
func (cc *SetupCmd) Run(ctx *RunContext) error {
	return setupWizard(ctx)
}

func setupWizard(ctx *RunContext) error {
	var err error
	var instanceName, startURL, ssoRegion, awsRegion, urlAction string

	// Name our SSO instance
	prompt := promptui.Prompt{
		Label:    "SSO Instance Name",
		Validate: validateSSOName,
		Default:  ctx.Cli.SSO,
	}
	if instanceName, err = prompt.Run(); err != nil {
		return err
	}

	// Get the full AWS SSO start URL
	prompt = promptui.Prompt{
		Label:    "SSO Start URL (StartUrl)",
		Validate: validateSSOUrl,
		Default:  ctx.Cli.Setup.SSOStartUrl,
	}
	if startURL, err = prompt.Run(); err != nil {
		return err
	}

	// Pick our AWS SSO region
	sel := promptui.Select{
		Label:        "AWS SSO Region (SSORegion)",
		Items:        AvailableAwsSSORegions,
		HideSelected: false,
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
		sel = promptui.Select{
			Label:        "Default region for connecting to AWS (DefaultRegion)",
			Items:        defaultRegions,
			HideSelected: false,
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
		sel = promptui.Select{
			Label: "Default action to take with URLs (UrlAction)",
			Items: []string{"open", "print", "clip"},
		}
		if _, urlAction, err = sel.Run(); err != nil {
			return err
		}
	}

	// write config file
	s := sso.Settings{
		DefaultSSO: instanceName,
		SSO:        map[string]*sso.SSOConfig{},
		UrlAction:  urlAction,
	}
	s.SSO[ctx.Cli.SSO] = &sso.SSOConfig{
		SSORegion:     ssoRegion,
		StartUrl:      startURL,
		DefaultRegion: awsRegion,
	}
	return s.Save(ctx.Cli.ConfigFile, false)
}

// validateSSOUrl verifies our SSO Start url is in the format of http://xxxxx.awsapps.com/start
// and the FQDN is valid
func validateSSOUrl(input string) error {
	u, err := url.Parse(input)
	if err != nil {
		return err
	}

	if !strings.HasPrefix(input, "https://") {
		return fmt.Errorf("URL must start with https://")
	}

	if u.Path != "/start" {
		return fmt.Errorf("AWS SSO URL must end in: /start")
	}

	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		host = u.Host
	}

	if !strings.Contains(host, ".awsapps.com") {
		return fmt.Errorf("Invalid FQDN.  Must be of the format of: xxxxxx.awsapps.com")
	}

	_, err = net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("Invalid FQDN in AWS SSO URL: %s", u.Host)
	}

	return nil
}

// validateSSOName just makes sure we have some text
func validateSSOName(input string) error {
	if len(input) > 0 {
		return nil
	}
	return fmt.Errorf("SSO Name must be a valid string")
}

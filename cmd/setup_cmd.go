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

// SetupCmd defines the Kong args for the setup command (which currently doesn't exist)
type SetupCmd struct {
	SSOStartUrl string `kong:"help='AWS SSO User Portal URL'"`
	SSORegion   string `kong:"help='AWS SSO Instance Region'"`
	Force       bool   `kong:"help='Force override of existing config file'"`
}

// Run executes the setup command
func (cc *SetupCmd) Run(ctx *RunContext) error {
	return setupWizard(ctx)
}

func setupWizard(ctx *RunContext) error {
	var err error
	var instanceName, startURL, ssoRegion string

	prompt := promptui.Prompt{
		Label:    "SSO Instance Name",
		Validate: validateSSOName,
		Default:  ctx.Cli.SSO,
	}
	if instanceName, err = prompt.Run(); err != nil {
		return err
	}

	prompt = promptui.Prompt{
		Label:    "SSO Start URL",
		Validate: validateSSOUrl,
	}
	if startURL, err = prompt.Run(); err != nil {
		return err
	}

	prompt = promptui.Prompt{
		Label:    "SSO Region",
		Validate: validateAwsRegion,
	}
	if ssoRegion, err = prompt.Run(); err != nil {
		return err
	}

	s := sso.Settings{
		DefaultSSO: instanceName,
		SSO:        map[string]*sso.SSOConfig{},
	}
	s.SSO[ctx.Cli.SSO] = &sso.SSOConfig{
		SSORegion: ssoRegion,
		StartUrl:  startURL,
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

	if u.Path != "/start" {
		return fmt.Errorf("AWS SSO URL must end in: /start")
	}

	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		host = u.Host
	}

	if !strings.Contains(host, ".awsapps.com") {
		return fmt.Errorf("Invalid FQDN")
	}

	_, err = net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("Unable to lookup FQDN in AWS SSO URL: %s, %s", u.Host, err)
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

func validateAwsRegion(input string) error {
	for _, v := range AvailableAwsSSORegions {
		if input == v {
			return nil
		}
	}
	return fmt.Errorf("Invalid AWS SSO region")
}

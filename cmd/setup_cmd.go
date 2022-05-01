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

	"github.com/synfinatic/aws-sso-cli/sso"
)

// SetupCmd defines the Kong args for the setup command (which currently doesn't exist)
type SetupCmd struct {
	DefaultRegion    string `kong:"help='Default AWS region for running commands (or \"None\")'"`
	SSOStartHostname string `kong:"help='AWS SSO User Portal Hostname'"`
	SSORegion        string `kong:"help='AWS SSO Instance Region'"`
	HistoryLimit     int64  `kong:"help='Number of items to keep in History',default=-1"`
	HistoryMinutes   int64  `kong:"help='Number of minutes to keep items in History',default=-1"`
	DefaultLevel     string `kong:"help='Logging level [error|warn|info|debug|trace]'"`
	Force            bool   `kong:"help='Force override of existing config file'"`
	FirefoxPath      string `kong:"help='Path to the Firefox web browser'"`
	RanSetup         bool   `kong:"hidden"` // track if setup has already run
}

// Run executes the setup command
func (cc *SetupCmd) Run(ctx *RunContext) error {
	return setupWizard(ctx)
}

func setupWizard(ctx *RunContext) error {
	var err error
	var instanceName, startHostname, ssoRegion, awsRegion, urlAction string
	var logLevel, firefoxBrowserPath, browser string
	var hLimit, hMinutes int64
	urlExecCommand := []string{}
	firefoxOpenUrlInContainer := false

	// Don't run setup twice
	if ctx.Cli.Setup.RanSetup {
		return nil
	}
	ctx.Cli.Setup.RanSetup = true

	if ctx.Cli.Setup.DefaultLevel != "" {
		if err := logLevelValidate(ctx.Cli.Setup.DefaultLevel); err != nil {
			log.Fatalf("Invalid value for --default-level %s", ctx.Cli.Setup.DefaultLevel)
		}
	}

	if instanceName, err = promptSsoInstance(ctx.Cli.SSO); err != nil {
		return err
	}

	if startHostname, err = promptStartUrl(ctx.Cli.Setup.SSOStartHostname); err != nil {
		return err
	}

	if ssoRegion, err = promptAwsSsoRegion(ctx.Cli.Setup.SSORegion); err != nil {
		return err
	}

	if awsRegion, err = promptDefaultRegion(ctx.Cli.Setup.DefaultRegion); err != nil {
		return err
	}

	if firefoxBrowserPath, err = promptUseFirefox(ctx.Cli.Setup.FirefoxPath); err != nil {
		return err
	}

	if firefoxBrowserPath != "" {
		firefoxOpenUrlInContainer = true
		urlAction = "exec"
		urlExecCommand = []string{
			firefoxBrowserPath,
			`%s`,
		}
	} else {
		if urlAction, err = promptUrlAction(); err != nil {
			return err
		}

		if urlAction == "open" {
			if browser, err = promptDefaultBrowser(ctx.Cli.Browser); err != nil {
				return err
			}
		}
	}

	if hLimit, err = promptHistoryLimit(ctx.Cli.Setup.HistoryLimit); err != nil {
		return err
	}

	if hMinutes, err = promptHistoryMinutes(ctx.Cli.Setup.HistoryMinutes); err != nil {
		return err
	}

	if logLevel, err = promptLogLevel(ctx.Cli.Setup.DefaultLevel); err != nil {
		return err
	}

	// write config file
	s := sso.Settings{
		DefaultSSO:                instanceName,
		SSO:                       map[string]*sso.SSOConfig{},
		UrlAction:                 urlAction,
		UrlExecCommand:            urlExecCommand,
		FirefoxOpenUrlInContainer: firefoxOpenUrlInContainer,
		Browser:                   browser,
		HistoryLimit:              hLimit,
		HistoryMinutes:            hMinutes,
		LogLevel:                  logLevel,
	}
	s.SSO[instanceName] = &sso.SSOConfig{
		SSORegion:     ssoRegion,
		StartUrl:      fmt.Sprintf(START_URL_FORMAT, startHostname),
		DefaultRegion: awsRegion,
	}
	return s.Save(ctx.Cli.ConfigFile, false)
}

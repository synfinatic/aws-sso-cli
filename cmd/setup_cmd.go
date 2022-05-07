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
	"io"
	"os"
	"time"

	"github.com/manifoldco/promptui"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
	"github.com/synfinatic/aws-sso-cli/sso"
)

var ranSetup = false

// SetupCmd defines the Kong args for the setup command (which currently doesn't exist)
type SetupCmd struct{}

// Run executes the setup command
func (cc *SetupCmd) Run(ctx *RunContext) error {
	return setupWizard(ctx, false, false)
}

type ReconfigCmd struct {
	AddSSO bool `kong:"help='Add a new AWS SSO instance'"`
}

func (cc *ReconfigCmd) Run(ctx *RunContext) error {
	// backup our config file
	var val string
	var err error

	label := "Backup ~/.aws-sso/config.yaml first?"
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
		return err
	}
	if val == "Yes" {
		src, err := os.Open(utils.GetHomePath("~/.aws-sso/config.yaml"))
		if err != nil {
			return err
		}

		newFile := fmt.Sprintf("~/.aws-sso/config-%s.yaml",
			time.Now().Format("2006-01-02-15:04:05"))
		dst, err := os.Create(utils.GetHomePath(newFile))
		if err != nil {
			return err
		}
		if _, err = io.Copy(dst, src); err != nil {
			return err
		}

		src.Close()
		dst.Close()
		fmt.Printf("Wrote: %s\n\n", newFile)
	}

	return setupWizard(ctx, true, ctx.Cli.Reconfig.AddSSO)
}

func setupWizard(ctx *RunContext, reconfig, addSSO bool) error {
	var instanceName, startHostname, ssoRegion, defaultRegion, urlAction string
	var defaultLevel, firefoxBrowserPath, browser, configProfilesUrlAction string
	var hLimit, hMinutes, cacheRefresh int64
	var consoleDuration int32
	var autoConfigCheck bool
	urlExecCommand := []interface{}{}

	// Don't run setup twice
	if ranSetup {
		return nil
	}
	ranSetup = true

	fmt.Printf(`**********************************************************************
* Do you have questions?  Do you like reading docs?  We've got docs! *
* https://github.com/synfinatic/aws-sso-cli/blob/main/docs/config.md *
**********************************************************************

`)

	if reconfig {
		defaultLevel = ctx.Settings.LogLevel
		defaultRegion = ctx.Settings.DefaultRegion
		urlAction = ctx.Settings.UrlAction
		urlExecCommand = ctx.Settings.UrlExecCommand.([]interface{})
		if ctx.Settings.FirefoxOpenUrlInContainer {
			firefoxBrowserPath = urlExecCommand[0].(string)
			ctx.Settings.FirefoxOpenUrlInContainer = true
		}
		autoConfigCheck = ctx.Settings.AutoConfigCheck
		cacheRefresh = ctx.Settings.CacheRefresh
		hLimit = ctx.Settings.HistoryLimit
		hMinutes = ctx.Settings.HistoryMinutes
		browser = ctx.Settings.Browser
		consoleDuration = ctx.Settings.ConsoleDuration

		// upgrade deprecated config option
		configProfilesUrlAction = ctx.Settings.ConfigProfilesUrlAction
		if ctx.Settings.ConfigUrlAction != "" && configProfilesUrlAction == "" {
			configProfilesUrlAction = ctx.Settings.ConfigUrlAction
		}
		// skips:
		// - SSORegion
		// - DefaultRegion
		// - StartUrl/startHostname
		// - InstanceName
	} else {
		hMinutes = 1440
		hLimit = 10
		defaultLevel = "warn"
	}

	if err := logLevelValidate(defaultLevel); err != nil {
		log.Fatalf("Invalid value for --default-level %s", defaultLevel)
	}

	if !reconfig {
		instanceName = promptSsoInstance("")
		startHostname = promptStartUrl("")
		ssoRegion = promptAwsSsoRegion("")
		defaultRegion = promptDefaultRegion(defaultRegion)

		ctx.Settings.SSO[instanceName] = &sso.SSOConfig{
			SSORegion:     ssoRegion,
			StartUrl:      fmt.Sprintf(START_URL_FORMAT, startHostname),
			DefaultRegion: defaultRegion,
		}
	} else if reconfig {
		// don't do anything with the SSO for reconfig
	} else if addSSO {
		log.Errorf("sorry, not supported yet")
	}

	ctx.Settings.AutoConfigCheck = promptAutoConfigCheck(autoConfigCheck)

	if ctx.Settings.AutoConfigCheck {
		ctx.Settings.CacheRefresh = promptCacheRefresh(cacheRefresh)
	}

	// First check if using Firefox w/ Containers
	firefoxBrowserPath = promptUseFirefox(firefoxBrowserPath)

	// if yes, then configure urlAction = 'exec' and our UrlExecCommand
	if firefoxBrowserPath != "" {
		ctx.Settings.FirefoxOpenUrlInContainer = true
		ctx.Settings.UrlAction = "exec"
		ctx.Settings.UrlExecCommand = []string{
			firefoxBrowserPath,
			`%s`,
		}
	} else {
		ctx.Settings.FirefoxOpenUrlInContainer = false
		// otherwise, prompt for our UrlAction and possibly browser
		ctx.Settings.UrlAction = promptUrlAction(urlAction)

		switch ctx.Settings.UrlAction {
		case "open":
			ctx.Settings.Browser = promptDefaultBrowser(browser)

		case "exec":
			ctx.Settings.UrlExecCommand = promptUrlExecCommand(urlExecCommand)
		}
	}

	ctx.Settings.ConfigProfilesUrlAction = promptConfigProfilesUrlAction(configProfilesUrlAction)
	ctx.Settings.ConsoleDuration = promptConsoleDuration(consoleDuration)
	ctx.Settings.HistoryLimit = promptHistoryLimit(hLimit)
	ctx.Settings.HistoryMinutes = promptHistoryMinutes(hMinutes)
	ctx.Settings.LogLevel = promptLogLevel(defaultLevel)
	fmt.Printf("\nAwesome!  Saving the new %s\n", ctx.Cli.ConfigFile)
	return ctx.Settings.Save(ctx.Cli.ConfigFile, reconfig)
}

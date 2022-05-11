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
	"path"
	"strings"
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

type ConfigCmd struct {
	// 	AddSSO bool `kong:"help='Add a new AWS SSO instance'"`
}

func (cc *ConfigCmd) Run(ctx *RunContext) error {
	// backup our config file
	var i int
	var err error

	label := fmt.Sprintf("Backup %s first?", ctx.Cli.ConfigFile)
	sel := promptui.Select{
		Label:        label,
		Items:        yesNoItems,
		CursorPos:    yesNoPos(true),
		HideSelected: false,
		Stdout:       &utils.BellSkipper{},
		Templates:    makeSelectTemplate(label),
	}
	if i, _, err = sel.Run(); err != nil {
		return err
	}

	if yesNoItems[i].Value == "Yes" {
		sourcePath := utils.GetHomePath(ctx.Cli.ConfigFile)
		src, err := os.Open(sourcePath)
		if err != nil {
			return err
		}

		dir := path.Dir(sourcePath)
		fileName := path.Base(sourcePath)
		fileparts := strings.Split(fileName, ".")
		ext := "yaml"
		if len(fileparts) > 1 {
			ext = fileparts[len(fileparts)-1]
			fileparts = fileparts[:len(fileparts)-1]
		}

		fileparts = append(fileparts, time.Now().Format("2006-01-02-15:04:05"))
		fileparts = append(fileparts, ext)

		newFile := strings.Join(fileparts, ".")
		newFile = path.Join(dir, newFile)

		dst, err := os.Create(newFile)
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

	return setupWizard(ctx, true, false) // ctx.Cli.Config.AddSSO)
}

func setupWizard(ctx *RunContext, reconfig, addSSO bool) error {
	var instanceName, startHostname, ssoRegion, defaultRegion, urlAction string
	var defaultLevel, firefoxBrowserPath, browser, configProfilesUrlAction string
	var hLimit, hMinutes, cacheRefresh int64
	var consoleDuration int32
	var autoConfigCheck bool
	var urlExecCommand []string

	// Don't run setup twice
	if ranSetup {
		return nil
	}
	ranSetup = true

	fmt.Printf(`
**********************************************************************
* Do you have questions?  Do you like reading docs?  We've got docs! *
* https://github.com/synfinatic/aws-sso-cli/blob/main/docs/config.md *
**********************************************************************

`)

	if reconfig {
		defaultLevel = ctx.Settings.LogLevel
		defaultRegion = ctx.Settings.DefaultRegion
		urlAction = ctx.Settings.UrlAction
		urlExecCommand = ctx.Settings.UrlExecCommand
		if ctx.Settings.FirefoxOpenUrlInContainer {
			firefoxBrowserPath = urlExecCommand[0]
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
			ctx.Settings.ConfigUrlAction = ""
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

		ctx.Settings = &sso.Settings{}
		ctx.Settings.SSO = map[string]*sso.SSOConfig{}

		ctx.Settings.SSO[instanceName] = &sso.SSOConfig{
			SSORegion:     ssoRegion,
			StartUrl:      fmt.Sprintf(START_URL_FORMAT, startHostname),
			DefaultRegion: defaultRegion,
		}
		consoleDuration = 60
		cacheRefresh = 168
		autoConfigCheck = false
		hLimit = 10
		hMinutes = 1440
		urlAction = "open"
		defaultLevel = "error"
	} else if reconfig {
		// don't do anything with the SSO for reconfig
	} else if addSSO {
		log.Errorf("sorry, not supported yet")
	}

	ctx.Settings.CacheRefresh = promptCacheRefresh(cacheRefresh)

	if ctx.Settings.CacheRefresh > 0 {
		ctx.Settings.AutoConfigCheck = promptAutoConfigCheck(autoConfigCheck)
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
		// Not using firefox containers...
		ctx.Settings.FirefoxOpenUrlInContainer = false
		ctx.Settings.UrlAction = promptUrlAction(urlAction, ctx.Settings.FirefoxOpenUrlInContainer)
	}

	ctx.Settings.ConfigProfilesUrlAction = promptConfigProfilesUrlAction(
		configProfilesUrlAction, ctx.Settings.UrlAction, ctx.Settings.FirefoxOpenUrlInContainer)

	// should we prompt user to override default browser?
	if ctx.Settings.UrlAction == "open" || ctx.Settings.ConfigProfilesUrlAction == "open" {
		ctx.Settings.Browser = promptDefaultBrowser(browser)
	}

	// Does either action call `exec` without firefox containers?
	if ctx.Settings.UrlAction == "exec" || ctx.Settings.ConfigProfilesUrlAction == "exec" {
		if !ctx.Settings.FirefoxOpenUrlInContainer {
			ctx.Settings.UrlExecCommand = promptUrlExecCommand(urlExecCommand)
		}
	}

	ctx.Settings.ConsoleDuration = promptConsoleDuration(consoleDuration)
	ctx.Settings.HistoryLimit = promptHistoryLimit(hLimit)
	ctx.Settings.HistoryMinutes = promptHistoryMinutes(hMinutes)
	ctx.Settings.LogLevel = promptLogLevel(defaultLevel)
	fmt.Printf("\nAwesome!  Saving the new %s\n", ctx.Cli.ConfigFile)
	return ctx.Settings.Save(ctx.Cli.ConfigFile, reconfig)
}

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
		log.Infof("wrote %s", newFile)
	}

	return setupWizard(ctx, true, ctx.Cli.Reconfig.AddSSO)
}

func setupWizard(ctx *RunContext, reconfig, addSSO bool) error {
	var err error
	var instanceName, startHostname, ssoRegion, defaultRegion, urlAction string
	var defaultLevel, firefoxBrowserPath, browser, configUrlAction string
	var hLimit, hMinutes, cacheRefresh int64
	var autoConfigCheck bool
	urlExecCommand := []string{}

	// Don't run setup twice
	if ranSetup {
		return nil
	}
	ranSetup = true

	if reconfig {
		defaultLevel = ctx.Settings.LogLevel
		cacheRefresh = ctx.Settings.CacheRefresh
		defaultRegion = ctx.Settings.DefaultRegion
		urlAction = ctx.Settings.UrlAction
		urlExecCommand = ctx.Settings.UrlExecCommand.([]string)
		if ctx.Settings.FirefoxOpenUrlInContainer {
			firefoxBrowserPath = urlExecCommand[0]
			ctx.Settings.FirefoxOpenUrlInContainer = true
		}
		autoConfigCheck = ctx.Settings.AutoConfigCheck
		configUrlAction = ctx.Settings.ConfigUrlAction
		hLimit = ctx.Settings.HistoryLimit
		hMinutes = ctx.Settings.HistoryMinutes
		browser = ctx.Settings.Browser
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
		if instanceName, err = promptSsoInstance(""); err != nil {
			return err
		}

		if startHostname, err = promptStartUrl(""); err != nil {
			return err
		}

		if ssoRegion, err = promptAwsSsoRegion(""); err != nil {
			return err
		}

		if defaultRegion, err = promptDefaultRegion(defaultRegion); err != nil {
			return err
		}

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

	if ctx.Settings.AutoConfigCheck, err = promptAutoConfigCheck(autoConfigCheck); err != nil {
		return err
	}

	if ctx.Settings.AutoConfigCheck {
		if ctx.Settings.CacheRefresh, err = promptCacheRefresh(cacheRefresh); err != nil {
			return err
		}
	}

	// First check if using Firefox w/ Containers
	if firefoxBrowserPath, err = promptUseFirefox(firefoxBrowserPath); err != nil {
		return err
	}

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
		if ctx.Settings.UrlAction, err = promptUrlAction(urlAction); err != nil {
			return err
		}

		switch ctx.Settings.UrlAction {
		case "open":
			if ctx.Settings.UrlAction, err = promptDefaultBrowser(browser); err != nil {
				return err
			}

		case "exec":
			if ctx.Settings.UrlExecCommand, err = promptUrlExecCommand(urlExecCommand); err != nil {
				return err
			}
		}
	}

	// Only prompt for ConfigUrlAction is UrlAction is not valid or different
	if utils.StrListContains(urlAction, CONFIG_OPEN_OPTIONS) || urlAction != configUrlAction {
		ctx.Settings.ConfigUrlAction = urlAction
	} else {
		if ctx.Settings.ConfigUrlAction, err = promptConfigUrlAction(configUrlAction); err != nil {
			return err
		}
	}

	if ctx.Settings.HistoryLimit, err = promptHistoryLimit(hLimit); err != nil {
		return err
	}

	if ctx.Settings.HistoryMinutes, err = promptHistoryMinutes(hMinutes); err != nil {
		return err
	}

	if ctx.Settings.LogLevel, err = promptLogLevel(defaultLevel); err != nil {
		return err
	}
	return ctx.Settings.Save(ctx.Cli.ConfigFile, reconfig)
}

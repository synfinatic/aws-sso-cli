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
	"errors"
	"fmt"
	"os"

	"github.com/alecthomas/kong"
	"github.com/posener/complete"
	// "github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"
	"github.com/synfinatic/aws-sso-cli/internal/awsconfig"
	"github.com/synfinatic/aws-sso-cli/internal/helper"
	"github.com/synfinatic/aws-sso-cli/internal/predictor"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	"github.com/synfinatic/aws-sso-cli/internal/url"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
	"github.com/synfinatic/aws-sso-cli/sso"
	"github.com/willabides/kongplete"
)

// These variables are defined in the Makefile
var Version = "unknown"
var Buildinfos = "unknown"
var Tag = "NO-TAG"
var CommitID = "unknown"
var Delta = ""
var VALID_LOG_LEVELS = []string{"error", "warn", "info", "debug", "trace"}

type RunContext struct {
	Kctx     *kong.Context
	Cli      *CLI
	Settings *sso.Settings // unified config & cache
	Store    storage.SecureStorage
}

const (
	CONFIG_DIR          = "~/.aws-sso"
	CONFIG_FILE         = CONFIG_DIR + "/config.yaml"
	JSON_STORE_FILE     = CONFIG_DIR + "/store.json"
	INSECURE_CACHE_FILE = CONFIG_DIR + "/cache.json"
	DEFAULT_STORE       = "file"
	COPYRIGHT_YEAR      = "2021-2022"
)

var DEFAULT_CONFIG map[string]interface{} = map[string]interface{}{
	"PromptColors.DescriptionBGColor":           "Turquoise",
	"PromptColors.DescriptionTextColor":         "Black",
	"PromptColors.InputBGColor":                 "DefaultColor",
	"PromptColors.InputTextColor":               "DefaultColor",
	"PromptColors.PrefixBackgroundColor":        "DefaultColor",
	"PromptColors.PrefixTextColor":              "Blue",
	"PromptColors.PreviewSuggestionBGColor":     "DefaultColor",
	"PromptColors.PreviewSuggestionTextColor":   "Green",
	"PromptColors.ScrollbarBGColor":             "Cyan",
	"PromptColors.ScrollbarThumbColor":          "LightGrey",
	"PromptColors.SelectedDescriptionBGColor":   "DarkGray",
	"PromptColors.SelectedDescriptionTextColor": "White",
	"PromptColors.SelectedSuggestionBGColor":    "DarkGray",
	"PromptColors.SelectedSuggestionTextColor":  "White",
	"PromptColors.SuggestionBGColor":            "Cyan",
	"PromptColors.SuggestionTextColor":          "White",
	"DefaultRegion":                             "us-east-1",
	"HistoryLimit":                              10,
	"HistoryMinutes":                            1440, // 24hrs
	"ListFields":                                []string{"AccountId", "AccountAlias", "RoleName", "Profile", "ExpiresStr"},
	"ConsoleDuration":                           60,
	"UrlAction":                                 "open",
	"ConfigProfilesUrlAction":                   "open",
	"LogLevel":                                  "warn",
	"DefaultSSO":                                "Default",
	"FirefoxOpenUrlInContainer":                 false,
	"AutoConfigCheck":                           false,
	"ProfileFormat":                             `{{ AccountIdStr .AccountId }}:{{ .RoleName }}`,
	"CacheRefresh":                              24, // in hours
	"Threads":                                   5,
}

type CLI struct {
	// Common Arguments
	Browser       string `kong:"short='b',help='Path to browser to open URLs with',env='AWS_SSO_BROWSER'"`
	ConfigFile    string `kong:"name='config',default='${CONFIG_FILE}',help='Config file',env='AWS_SSO_CONFIG'"`
	LogLevel      string `kong:"short='L',name='level',help='Logging level [error|warn|info|debug|trace] (default: warn)'"`
	Lines         bool   `kong:"help='Print line number in logs'"`
	UrlAction     string `kong:"short='u',help='How to handle URLs [clip|exec|open|print|printurl|granted-containers|open-url-in-container] (default: open)'"`
	SSO           string `kong:"short='S',help='Override default AWS SSO Instance',env='AWS_SSO',predictor='sso'"`
	STSRefresh    bool   `kong:"help='Force refresh of STS Token Credentials'"`
	NoConfigCheck bool   `kong:"help='Disable automatic ~/.aws/config updates'"`
	Threads       int    `kong:"help='Override number of threads for talking to AWS'"`

	// Commands
	Cache          CacheCmd          `kong:"cmd,help='Force reload of cached AWS SSO role info and config.yaml'"`
	Console        ConsoleCmd        `kong:"cmd,help='Open AWS Console using specificed AWS role/profile'"`
	Default        DefaultCmd        `kong:"cmd,hidden,default='1'"` // list command without args
	Eval           EvalCmd           `kong:"cmd,help='Print AWS environment vars for use with eval $(aws-sso eval ...)'"`
	Exec           ExecCmd           `kong:"cmd,help='Execute command using specified IAM role in a new shell'"`
	Flush          FlushCmd          `kong:"cmd,help='Flush AWS SSO/STS credentials from cache'"`
	List           ListCmd           `kong:"cmd,help='List all accounts / roles (default command)'"`
	Process        ProcessCmd        `kong:"cmd,help='Generate JSON for credential_process in ~/.aws/config'"`
	Static         StaticCmd         `kong:"cmd,help='Manage static AWS API credentials',hidden"`
	Tags           TagsCmd           `kong:"cmd,help='List tags'"`
	Time           TimeCmd           `kong:"cmd,help='Print how much time before current STS Token expires'"`
	Completions    CompleteCmd       `kong:"cmd,help='Manage shell completions'"`
	ConfigProfiles ConfigProfilesCmd `kong:"cmd,help='Update ~/.aws/config with AWS SSO profiles from the cache'"`
	Config         ConfigCmd         `kong:"cmd,help='Run the configuration wizard'"`
	Version        VersionCmd        `kong:"cmd,help='Print version and exit'"`
	Setup          SetupCmd          `kong:"cmd,hidden"` // need this so variables are visisble.
}

func main() {
	cli := CLI{}
	var err error

	log = logrus.New()
	ctx, override := parseArgs(&cli)
	awsconfig.SetLogger(log)
	helper.SetLogger(log)
	predictor.SetLogger(log)
	sso.SetLogger(log)
	storage.SetLogger(log)
	url.SetLogger(log)
	utils.SetLogger(log)

	if err := logLevelValidate(cli.LogLevel); err != nil {
		log.Fatalf("%s", err.Error())
	}

	runCtx := RunContext{
		Kctx: ctx,
		Cli:  &cli,
	}

	switch ctx.Command() {
	case "Version":
		if err = ctx.Run(&runCtx); err != nil {
			log.Fatalf("Error running command: %s", err.Error())
		}
		return
	}

	// Load the config file
	cli.ConfigFile = utils.GetHomePath(cli.ConfigFile)

	if _, err := os.Stat(cli.ConfigFile); errors.Is(err, os.ErrNotExist) {
		log.Warnf("No config file found!  Will now prompt you for a basic config...")
		if err = setupWizard(&runCtx, false, false); err != nil {
			log.Fatalf("%s", err.Error())
		}
	} else if err != nil {
		log.WithError(err).Fatalf("Unable to open config file: %s", cli.ConfigFile)
	}

	cacheFile := utils.GetHomePath(INSECURE_CACHE_FILE)

	if runCtx.Settings, err = sso.LoadSettings(cli.ConfigFile, cacheFile, DEFAULT_CONFIG, override); err != nil {
		log.Fatalf("%s", err.Error())
	}

	// Load the secure store data
	switch runCtx.Settings.SecureStore {
	case "json":
		sfile := utils.GetHomePath(JSON_STORE_FILE)
		if runCtx.Settings.JsonStore != "" {
			sfile = utils.GetHomePath(runCtx.Settings.JsonStore)
		}
		runCtx.Store, err = storage.OpenJsonStore(sfile)
		if err != nil {
			log.WithError(err).Fatalf("Unable to open JsonStore %s", sfile)
		}
		log.Warnf("Using insecure json file for SecureStore: %s", sfile)
	default:
		cfg, err := storage.NewKeyringConfig(runCtx.Settings.SecureStore, CONFIG_DIR)
		if err != nil {
			log.WithError(err).Fatalf("Unable to create SecureStore")
		}
		runCtx.Store, err = storage.OpenKeyring(cfg)
		if err != nil {
			log.WithError(err).Fatalf("Unable to open SecureStore %s", runCtx.Settings.SecureStore)
		}
	}

	err = ctx.Run(&runCtx)
	if err != nil {
		log.Fatalf("Error running command: %s", err.Error())
	}
}

// parseArgs parses our CLI arguments
func parseArgs(cli *CLI) (*kong.Context, sso.OverrideSettings) {
	// need to pass in the variables for defaults
	vars := kong.Vars{
		"CONFIG_DIR":      CONFIG_DIR,
		"CONFIG_FILE":     CONFIG_FILE,
		"DEFAULT_STORE":   DEFAULT_STORE,
		"JSON_STORE_FILE": JSON_STORE_FILE,
	}

	parser := kong.Must(
		cli,
		kong.Name("aws-sso"),
		kong.Description("Securely manage temporary AWS API Credentials issued via AWS SSO"),
		kong.UsageOnError(),
		vars,
	)

	p := predictor.NewPredictor(utils.GetHomePath(INSECURE_CACHE_FILE), utils.GetHomePath(CONFIG_FILE))

	kongplete.Complete(parser,
		kongplete.WithPredictors(
			map[string]complete.Predictor{
				"accountId": p.AccountComplete(),
				"arn":       p.ArnComplete(),
				"fieldList": p.FieldListComplete(),
				"profile":   p.ProfileComplete(),
				"region":    p.RegionComplete(),
				"role":      p.RoleComplete(),
				"sso":       p.SsoComplete(),
			},
		),
	)

	ctx, err := parser.Parse(os.Args[1:])
	parser.FatalIfErrorf(err)

	action, err := url.NewAction(cli.UrlAction)
	if err != nil {
		log.Fatalf("Invalid --url-action %s", cli.UrlAction)
	}

	override := sso.OverrideSettings{
		Browser:    cli.Browser,
		DefaultSSO: cli.SSO,
		LogLevel:   cli.LogLevel,
		LogLines:   cli.Lines,
		Threads:    cli.Threads,
		UrlAction:  action,
	}

	log.SetFormatter(&logrus.TextFormatter{
		DisableLevelTruncation: true,
		PadLevelText:           true,
		DisableTimestamp:       true,
	})

	return ctx, override
}

type VersionCmd struct{} // takes no arguments

func (cc *VersionCmd) Run(ctx *RunContext) error {
	delta := ""
	if len(Delta) > 0 {
		delta = fmt.Sprintf(" [%s delta]", Delta)
		Tag = "Unknown"
	}
	fmt.Printf("AWS SSO CLI Version %s -- Copyright %s Aaron Turner\n", Version, COPYRIGHT_YEAR)
	fmt.Printf("%s (%s)%s built at %s\n", CommitID, Tag, delta, Buildinfos)
	return nil
}

// Get our RoleCredentials from the secure store or from AWS SSO
func GetRoleCredentials(ctx *RunContext, awssso *sso.AWSSSO, accountid int64, role string) *storage.RoleCredentials {
	creds := storage.RoleCredentials{}

	// First look for our creds in the secure store, if we're not forcing a refresh
	arn := utils.MakeRoleARN(accountid, role)
	log.Debugf("Getting role credentials for %s", arn)
	if !ctx.Cli.STSRefresh {
		if roleFlat, err := ctx.Settings.Cache.GetRole(arn); err == nil {
			if !roleFlat.IsExpired() {
				if err := ctx.Store.GetRoleCredentials(arn, &creds); err == nil {
					if !creds.Expired() {
						log.Debugf("Retrieved role credentials from the SecureStore")
						return &creds
					}
				}
			}
		}
	} else {
		log.Infof("Forcing STS refresh for %s", arn)
	}

	log.Debugf("Fetching STS token from AWS SSO")

	// If we didn't use our secure store ask AWS SSO
	var err error
	creds, err = awssso.GetRoleCredentials(accountid, role)
	if err != nil {
		log.WithError(err).Fatalf("Unable to get role credentials for %s", arn)
	}

	log.Debugf("Retrieved role credentials from AWS SSO")

	// Cache our creds
	if err := ctx.Store.SaveRoleCredentials(arn, creds); err != nil {
		log.WithError(err).Warnf("Unable to cache role credentials in secure store")
	}

	// Update the cache
	if err := ctx.Settings.Cache.SetRoleExpires(arn, creds.ExpireEpoch()); err != nil {
		log.WithError(err).Warnf("Unable to update cache")
	}
	return &creds
}

var AwsSSO *sso.AWSSSO // global

// Creates a singleton AWSSO object post authentication
func doAuth(ctx *RunContext) *sso.AWSSSO {
	if AwsSSO != nil {
		return AwsSSO
	}
	s, err := ctx.Settings.GetSelectedSSO(ctx.Cli.SSO)
	if err != nil {
		log.Fatalf("%s", err.Error())
	}
	AwsSSO = sso.NewAWSSSO(s, &ctx.Store)
	err = AwsSSO.Authenticate(ctx.Settings.UrlAction, ctx.Settings.Browser)
	if err != nil {
		log.WithError(err).Fatalf("Unable to authenticate")
	}
	if err = ctx.Settings.Cache.Expired(s); err != nil {
		ssoName, err := ctx.Settings.GetSelectedSSOName(ctx.Cli.SSO)
		log.Infof("Refreshing AWS SSO role cache for %s, please wait...", ssoName)
		if err != nil {
			log.Fatalf(err.Error())
		}
		if err = ctx.Settings.Cache.Refresh(AwsSSO, s, ssoName); err != nil {
			log.WithError(err).Fatalf("Unable to refresh cache")
		}
		if err = ctx.Settings.Cache.Save(true); err != nil {
			log.WithError(err).Errorf("Unable to save cache")
		}

		// should we update our config??
		if !ctx.Cli.NoConfigCheck && ctx.Settings.AutoConfigCheck {
			if ctx.Settings.ConfigProfilesUrlAction != url.ConfigProfilesUndef {
				cfgFile := utils.GetHomePath("~/.aws/config")

				action, _ := url.NewAction(string(ctx.Settings.ConfigProfilesUrlAction))
				profiles, err := ctx.Settings.GetAllProfiles(action)
				if err != nil {
					log.Warnf("Unable to update %s: %s", cfgFile, err.Error())
					return AwsSSO
				}

				if err = profiles.UniqueCheck(ctx.Settings); err != nil {
					log.Errorf("Unable to update %s: %s", cfgFile, err.Error())
					return AwsSSO
				}

				f, err := utils.NewFileEdit(CONFIG_TEMPLATE, profiles)
				if err != nil {
					log.Errorf("%s", err)
					return AwsSSO
				}

				if err = f.UpdateConfig(true, false, cfgFile); err != nil {
					log.Errorf("Unable to update %s: %s", cfgFile, err.Error())
					return AwsSSO
				}
			}
		}
	}
	return AwsSSO
}

func logLevelValidate(level string) error {
	if utils.StrListContains(level, VALID_LOG_LEVELS) || level == "" {
		return nil
	}
	return fmt.Errorf("Invalid value for --level: %s", level)
}

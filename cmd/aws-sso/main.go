package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2023 Aaron Turner  <synfinatic at gmail dot com>
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
	"github.com/synfinatic/aws-sso-cli/internal/awscreds"
	"github.com/synfinatic/aws-sso-cli/internal/ecs"
	"github.com/synfinatic/aws-sso-cli/internal/ecs/client"
	"github.com/synfinatic/aws-sso-cli/internal/ecs/server"
	"github.com/synfinatic/aws-sso-cli/internal/helper"
	"github.com/synfinatic/aws-sso-cli/internal/predictor"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	"github.com/synfinatic/aws-sso-cli/internal/tags"
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

var AwsSSO *sso.AWSSSO // global

type RunContext struct {
	Kctx     *kong.Context
	Cli      *CLI
	Settings *sso.Settings // unified config & cache
	Store    storage.SecureStorage
	Override sso.OverrideSettings
}

const (
	CONFIG_DIR          = "~/.aws-sso"
	CONFIG_FILE         = CONFIG_DIR + "/config.yaml"
	JSON_STORE_FILE     = CONFIG_DIR + "/store.json"
	INSECURE_CACHE_FILE = CONFIG_DIR + "/cache.json"
	DEFAULT_STORE       = "file"
	COPYRIGHT_YEAR      = "2021-2023"
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
	"ConfigProfilesUrlAction":                   "open",
	"ConsoleDuration":                           60,
	"DefaultRegion":                             "us-east-1",
	"DefaultSSO":                                "Default",
	"FirefoxOpenUrlInContainer":                 false,
	"FullTextSearch":                            true,
	"HistoryLimit":                              10,
	"HistoryMinutes":                            1440, // 24hrs
	"ListFields":                                DEFAULT_LIST_FIELDS,
	"MaxBackoff":                                5, // seconds
	"MaxRetry":                                  10,
	"ProfileFormat":                             DEFAULT_PROFILE_FORMAT,
	"UrlAction":                                 "open",
	"LogLevel":                                  "warn",
	"Threads":                                   5,
}

type CLI struct {
	// Common Arguments
	Browser    string `kong:"short='b',help='Path to browser to open URLs with',env='AWS_SSO_BROWSER'"`
	ConfigFile string `kong:"name='config',default='${CONFIG_FILE}',help='Config file',env='AWS_SSO_CONFIG'"`
	LogLevel   string `kong:"short='L',name='level',help='Logging level [error|warn|info|debug|trace] (default: warn)'"`
	Lines      bool   `kong:"help='Print line number in logs'"`
	UrlAction  string `kong:"short='u',help='How to handle URLs [clip|exec|open|print|printurl|granted-containers|open-url-in-container] (default: open)'"`
	SSO        string `kong:"short='S',help='Override default AWS SSO Instance',env='AWS_SSO',predictor='sso'"`
	STSRefresh bool   `kong:"help='Force refresh of STS Token Credentials'"`

	// Commands
	Cache   CacheCmd   `kong:"cmd,help='Update cached AWS SSO role info'"`
	Console ConsoleCmd `kong:"cmd,help='Open AWS Console using specificed AWS role/profile'"`
	Default DefaultCmd `kong:"cmd,hidden,default='1'"` // list command without args
	Eval    EvalCmd    `kong:"cmd,help='Print AWS environment vars for use with eval $(aws-sso eval ...)'"`
	Exec    ExecCmd    `kong:"cmd,help='Execute command using specified IAM role in a new shell'"`
	List    ListCmd    `kong:"cmd,help='List all accounts / roles (default command)'"`
	Login   LoginCmd   `kong:"cmd,help='Login to AWS SSO'"`
	Logout  LogoutCmd  `kong:"cmd,help='Logout from AWS SSO and invalidate all credentials'"`
	Process ProcessCmd `kong:"cmd,help='Generate JSON for credential_process in ~/.aws/config'"`
	Static  StaticCmd  `kong:"cmd,hidden,help='Manage static AWS API credentials'"`
	Tags    TagsCmd    `kong:"cmd,help='List tags'"`
	Time    TimeCmd    `kong:"cmd,help='Print how much time before current STS Token expires'"`
	Setup   SetupCmd   `kong:"cmd,help='Setup aws-sso'"`
	Ecs     EcsCmd     `kong:"cmd,help='ECS Server commands'"`
	Version VersionCmd `kong:"cmd,help='Print version and exit'"`
}

func main() {
	cli := CLI{}
	var err error

	log = logrus.New()
	ctx, override := parseArgs(&cli)
	awscreds.SetLogger(log)
	helper.SetLogger(log)
	predictor.SetLogger(log)
	sso.SetLogger(log)
	storage.SetLogger(log)
	tags.SetLogger(log)
	url.SetLogger(log)
	utils.SetLogger(log)
	ecs.SetLogger(log)
	server.SetLogger(log)
	client.SetLogger(log)

	if err := logLevelValidate(cli.LogLevel); err != nil {
		log.Fatalf("%s", err.Error())
	}

	runCtx := RunContext{
		Kctx:     ctx,
		Cli:      &cli,
		Override: override,
	}

	switch ctx.Command() {
	case "version":
		if err = ctx.Run(&runCtx); err != nil {
			log.Fatalf("Error running command: %s", err.Error())
		}
		return
	}

	// Load the config file
	cli.ConfigFile = utils.GetHomePath(cli.ConfigFile)

	if _, err := os.Stat(cli.ConfigFile); errors.Is(err, os.ErrNotExist) {
		log.Warnf("No config file found!  Will now prompt you for a basic config...")
		setup := SetupAllCmd{}
		runCtx.Cli.Setup.Wizard.Reconfig = false
		runCtx.Cli.Setup.AwsConfig.Diff = true

		if err = setup.Run(&runCtx); err != nil {
			return
		}

		switch ctx.Command() {
		case "setup", "setup all", "setup wizard", "setup shell", "setup aws-config", "login":
			// we're done.
			return
		}
	} else if err != nil {
		log.WithError(err).Fatalf("Unable to open config file: %s", cli.ConfigFile)
	}

	cacheFile := utils.GetHomePath(INSECURE_CACHE_FILE)

	if runCtx.Settings, err = sso.LoadSettings(cli.ConfigFile, cacheFile, DEFAULT_CONFIG, override); err != nil {
		log.Fatalf("unable to load settings: %s", err.Error())
	}

	switch ctx.Command() {
	case "ecs run", "setup wizard", "setup all":
		break // do nothing

	case "list", "login", "ecs list", "ecs unload", "ecs profile":
		// Initialize our AwsSSO variable & SecureStore, but don't do any auth
		c := &runCtx
		s, err := c.Settings.GetSelectedSSO(c.Cli.SSO)
		if err != nil {
			log.Fatalf("%s", err.Error())
		}

		loadSecureStore(c)
		AwsSSO = sso.NewAWSSSO(s, &c.Store)

	default: // includes "ecs load", "setup shell" & "setup aws-config"
		// make sure we have authenticated via AWS SSO and init SecureStore
		loadSecureStore(&runCtx)
		if !checkAuth(&runCtx) {
			log.Fatalf("Must run `aws-sso login` before running `aws-sso %s`", ctx.Command())
		}
	}

	err = ctx.Run(&runCtx)
	if err != nil {
		log.Fatalf("Error running command: %s", err.Error())
	}
}

// loadSecureStore loads our secure store data for future access
func loadSecureStore(ctx *RunContext) {
	var err error
	switch ctx.Settings.SecureStore {
	case "json":
		sfile := utils.GetHomePath(JSON_STORE_FILE)
		if ctx.Settings.JsonStore != "" {
			sfile = utils.GetHomePath(ctx.Settings.JsonStore)
		}
		ctx.Store, err = storage.OpenJsonStore(sfile)
		if err != nil {
			log.WithError(err).Fatalf("Unable to open JsonStore %s", sfile)
		}
		log.Warnf("Using insecure json file for SecureStore: %s", sfile)
	default:
		cfg, err := storage.NewKeyringConfig(ctx.Settings.SecureStore, CONFIG_DIR)
		if err != nil {
			log.WithError(err).Fatalf("Unable to create SecureStore")
		}
		ctx.Store, err = storage.OpenKeyring(cfg)
		if err != nil {
			log.WithError(err).Fatalf("Unable to open SecureStore %s", ctx.Settings.SecureStore)
		}
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

	// only cache and login commands have `--threads` flag
	threads := 0
	if cli.Login.Threads > 0 {
		threads = cli.Login.Threads
	} else if cli.Cache.Threads > 0 {
		threads = cli.Cache.Threads
	}

	override := sso.OverrideSettings{
		Browser:    cli.Browser,
		DefaultSSO: cli.SSO,
		LogLevel:   cli.LogLevel,
		LogLines:   cli.Lines,
		Threads:    threads,
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

func logLevelValidate(level string) error {
	if utils.StrListContains(level, VALID_LOG_LEVELS) || level == "" {
		return nil
	}
	return fmt.Errorf("Invalid value for --level: %s", level)
}

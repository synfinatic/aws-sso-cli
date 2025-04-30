package main

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2025 Aaron Turner  <synfinatic at gmail dot com>
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
	"strings"

	"github.com/alecthomas/kong"
	"github.com/posener/complete"

	// "github.com/davecgh/go-spew/spew"

	"github.com/synfinatic/aws-sso-cli/internal/config"
	"github.com/synfinatic/aws-sso-cli/internal/predictor"
	"github.com/synfinatic/aws-sso-cli/internal/sso"
	"github.com/synfinatic/aws-sso-cli/internal/storage"
	"github.com/synfinatic/aws-sso-cli/internal/utils"
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

type CommandAuth int

const (
	AUTH_UNKNOWN   CommandAuth = iota
	AUTH_NO_CONFIG             // run command without loading config
	AUTH_SKIP                  // load config, but no need to SSO auth
	AUTH_REQUIRED              // load config and require SSO auth
)

type RunContext struct {
	Kctx     *kong.Context
	Cli      *CLI
	Settings *sso.Settings // unified config & cache
	Store    storage.SecureStorage
	Auth     CommandAuth
}

const (
	DEFAULT_STORE   = "file"
	COPYRIGHT_YEAR  = "2021-2025"
	DEFAULT_THREADS = 5
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
	"AutoConfigCheck":                           false,
	"AutoLogin":                                 false,
	"CacheRefresh":                              168, // 7 days in hours
	"ConfigProfilesUrlAction":                   "open",
	"ConsoleDuration":                           60,
	"DefaultRegion":                             "us-east-1",
	"DefaultSSO":                                "Default",
	"FirefoxOpenUrlInContainer":                 false,
	"FullTextSearch":                            true,
	"HistoryLimit":                              10,
	"HistoryMinutes":                            1440, // 24hrs
	"ListFields":                                DEFAULT_LIST_FIELDS,
	"UrlAction":                                 "open",
	"LogLevel":                                  "info",
	"ProfileFormat":                             NICE_PROFILE_FORMAT,
	"Threads":                                   DEFAULT_THREADS,
	"MaxBackoff":                                5, // seconds
	"MaxRetry":                                  10,
}

type LogLevelType string

func (level LogLevelType) Validate() error {
	if utils.StrListContains(string(level), VALID_LOG_LEVELS) || level == "" {
		return nil
	}
	return fmt.Errorf("invalid value: %s.  Must be one of: %s", level, strings.Join(VALID_LOG_LEVELS, ", "))
}

type CLI struct {
	// Common Arguments
	Browser    string       `kong:"short='b',help='Path to browser to open URLs with',env='AWS_SSO_BROWSER'"`
	ConfigFile string       `kong:"name='config',default='${CONFIG_FILE}',help='Config file',env='AWS_SSO_CONFIG',predict='allFiles'"`
	LogLevel   LogLevelType `kong:"short='L',name='level',help='Logging level [error|warn|info|debug|trace] (default: info)'"`
	Lines      bool         `kong:"help='Print line number in logs'"`
	SSO        string       `kong:"short='S',help='Override default AWS SSO Instance',env='AWS_SSO',predictor='sso'"`

	// Commands
	Default      DefaultCmd      `kong:"cmd,hidden,default='1'"` // list command without args
	Ecs          EcsCmd          `kong:"cmd,help='ECS server/client commands'"`
	List         ListCmd         `kong:"cmd,help='List all accounts / roles (default command)'"`
	Login        LoginCmd        `kong:"cmd,help='Login to an AWS Identity Center instance'"`
	ListSSORoles ListSSORolesCmd `kong:"cmd,hidden,help='List AWS SSO Roles (debugging)'"`
	Setup        SetupCmd        `kong:"cmd,help='Setup Wizard, Completions, Profiles, etc'"`
	Tags         TagsCmd         `kong:"cmd,help='List tags'"`
	Time         TimeCmd         `kong:"cmd,help='Print how much time before current STS Token expires'"`
	Version      VersionCmd      `kong:"cmd,help='Print version and exit'"`

	// Login Commands
	Cache       CacheCmd       `kong:"cmd,help='Force reload of cached AWS SSO role info and config.yaml',group='login-required'"`
	Console     ConsoleCmd     `kong:"cmd,help='Open AWS Console using specificed AWS role/profile',group='login-required'"`
	Credentials CredentialsCmd `kong:"cmd,help='Generate static AWS credentials for use with AWS CLI',group='login-required'"`
	Eval        EvalCmd        `kong:"cmd,help='Print AWS environment vars for use with eval $(aws-sso eval ...)',group='login-required'"`
	Exec        ExecCmd        `kong:"cmd,help='Execute command using specified IAM role in a new shell',group='login-required'"`
	Logout      LogoutCmd      `kong:"cmd,help='Logout from an AWS Identity Center instance and invalidate all credentials',group='login-required'"`
	Process     ProcessCmd     `kong:"cmd,help='Generate JSON for AWS SDK credential_process command',group='login-required'"`
}

func main() {
	cli := CLI{}
	var err error
	runCtx := RunContext{
		Cli:  &cli,
		Auth: AUTH_UNKNOWN,
	}

	override := parseArgs(&runCtx)

	if runCtx.Auth == AUTH_NO_CONFIG ||
		runCtx.Kctx.Command() == "setup completions" {
		// side-step the rest of the setup...
		if err = runCtx.Kctx.Run(&runCtx); err != nil {
			log.Fatal(err.Error())
		}
		return
	}

	// Load the config file
	runCtx.Cli.ConfigFile = utils.GetHomePath(runCtx.Cli.ConfigFile)

	if _, err := os.Stat(cli.ConfigFile); errors.Is(err, os.ErrNotExist) {
		log.Warn("No config file found!  Will now prompt you for a basic config...")
		if err = setupWizard(&runCtx, false, false, runCtx.Cli.Setup.Wizard.Advanced); err != nil {
			log.Fatal(err.Error())
		}
		if runCtx.Kctx.Command() == "setup wizard" {
			// don't run the wizard again, we're done.
			return
		}
	} else if err != nil {
		log.Fatal("Unable to open config file", "file", cli.ConfigFile, "error", err.Error())
	}

	cacheFile := config.InsecureCacheFile(true)

	if runCtx.Settings, err = sso.LoadSettings(runCtx.Cli.ConfigFile, cacheFile, DEFAULT_CONFIG, override); err != nil {
		log.Fatal(err.Error())
	}

	switch runCtx.Auth {
	case AUTH_REQUIRED:
		// make sure we have authenticated via AWS SSO and init SecureStore
		loadSecureStore(&runCtx)
		if !checkAuth(&runCtx) {
			if !runCtx.Settings.AutoLogin {
				log.Fatal(fmt.Sprintf("Must run `aws-sso login` before running `aws-sso %s`", runCtx.Kctx.Command()))
			}
			// perform our login automatically
			doAuth(&runCtx)
		}

	case AUTH_SKIP:
		// commands which don't need to be authenticated to SSO
		c := &runCtx
		s, err := c.Settings.GetSelectedSSO(c.Cli.SSO)
		if err != nil {
			log.Fatal(err.Error())
		}

		loadSecureStore(c)
		AwsSSO = sso.NewAWSSSO(s, &c.Store)
	case AUTH_UNKNOWN:
		log.Fatal("Internal error: AUTH_UNKNOWN, please open a bug report")
	}

	err = runCtx.Kctx.Run(&runCtx)
	if err != nil {
		log.Fatal(err.Error())
	}
}

// loadSecureStore loads our secure store data for future access
func loadSecureStore(ctx *RunContext) {
	var err error
	switch ctx.Settings.SecureStore {
	case "json":
		sfile := config.JsonStoreFile(true)
		if ctx.Settings.JsonStore != "" {
			sfile = utils.GetHomePath(ctx.Settings.JsonStore)
		}
		ctx.Store, err = storage.OpenJsonStore(sfile)
		if err != nil {
			log.Fatal("Unable to open JsonStore", "file", sfile, "error", err.Error())
		}
		log.Warn("Using insecure json file for SecureStore", "file", sfile)
	default:
		cfg, err := storage.NewKeyringConfig(ctx.Settings.SecureStore, config.ConfigDir(true))
		if err != nil {
			log.Fatal("Unable to create SecureStore", "error", err.Error())
		}
		ctx.Store, err = storage.OpenKeyring(cfg)
		if err != nil {
			log.Fatal("Unable to open SecureStore", "file", ctx.Settings.SecureStore, "error", err.Error())
		}
	}
}

// parseArgs parses our CLI arguments
func parseArgs(ctx *RunContext) sso.OverrideSettings {
	var err error

	// need to pass in the variables for defaults
	vars := kong.Vars{
		"CONFIG_DIR":      config.ConfigDir(false),
		"CONFIG_FILE":     config.ConfigFile(false),
		"DEFAULT_STORE":   DEFAULT_STORE,
		"DEFAULT_THREADS": fmt.Sprintf("%d", DEFAULT_THREADS),
		"JSON_STORE_FILE": config.JsonStoreFile(false),
		"VERSION":         Version,
	}

	help := kong.HelpOptions{
		NoExpandSubcommands: true,
	}

	groups := []kong.Group{
		{
			Title: "Commands requiring login:",
			Key:   "login-required",
		},
		{
			Title: "Add SSL Certificate/Key:",
			Key:   "add-ssl",
		},
	}

	cli := ctx.Cli

	parser := kong.Must(
		cli,
		kong.Name("aws-sso"),
		kong.Description("Securely manage temporary AWS API Credentials issued via AWS SSO"),
		kong.ConfigureHelp(help),
		vars,
		kong.ExplicitGroups(groups),
		kong.Bind(ctx),
	)

	p := predictor.NewPredictor(config.InsecureCacheFile(true), config.ConfigFile(true))

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
				"allFiles":  complete.PredictFiles("*"),
			},
		),
	)

	ctx.Kctx, err = parser.Parse(os.Args[1:])
	parser.FatalIfErrorf(err)

	threads := 0
	if cli.Cache.Threads != DEFAULT_THREADS {
		threads = cli.Cache.Threads
	} else if cli.Login.Threads != DEFAULT_THREADS {
		threads = cli.Login.Threads
	}

	override := sso.OverrideSettings{
		Browser:    cli.Browser,
		DefaultSSO: cli.SSO,
		LogLevel:   string(cli.LogLevel),
		LogLines:   cli.Lines,
		Threads:    threads, // must be > 0 to override config
	}

	return override
}

type VersionCmd struct{} // takes no arguments

func (v VersionCmd) BeforeReset(ctx *RunContext) error {
	delta := ""
	if len(Delta) > 0 {
		delta = fmt.Sprintf(" [%s delta]", Delta)
		Tag = "Unknown"
	}
	fmt.Printf("AWS SSO CLI Version %s -- Copyright %s Aaron Turner\n", Version, COPYRIGHT_YEAR)
	fmt.Printf("%s (%s)%s built at %s\n", CommitID, Tag, delta, Buildinfos)
	os.Exit(0)
	return nil
}

func (cc *VersionCmd) Run(ctx *RunContext) error {
	return nil
}

// Get our RoleCredentials from the secure store or from AWS SSO
func GetRoleCredentials(ctx *RunContext, awssso *sso.AWSSSO, refreshSTS bool, accountid int64, role string) *storage.RoleCredentials {
	creds := storage.RoleCredentials{}

	// First look for our creds in the secure store, if we're not forcing a refresh
	arn := utils.MakeRoleARN(accountid, role)
	log.Debug("Getting role credentials", "arn", arn)
	if !refreshSTS {
		if roleFlat, err := ctx.Settings.Cache.GetRole(arn); err == nil {
			if !roleFlat.IsExpired() {
				if err := ctx.Store.GetRoleCredentials(arn, &creds); err == nil {
					if !creds.Expired() {
						log.Debug("Retrieved role credentials from the SecureStore")
						return &creds
					}
				}
			}
		}
	} else {
		log.Info("Forcing STS refresh", "arn", arn)
	}

	log.Debug("Fetching STS token from AWS SSO")

	// If we didn't use our secure store ask AWS SSO
	var err error
	creds, err = awssso.GetRoleCredentials(accountid, role)
	if err != nil {
		log.Fatal("Unable to get role credentials", "arn", arn, "error", err.Error())
	}

	log.Debug("Retrieved role credentials from AWS SSO")

	// Cache our creds
	if err := ctx.Store.SaveRoleCredentials(arn, creds); err != nil {
		log.Warn("Unable to cache role credentials in secure store", "error", err.Error())
	}

	// Update the cache
	if err := ctx.Settings.Cache.SetRoleExpires(arn, creds.ExpireEpoch()); err != nil {
		log.Warn("Unable to update cache", "error", err.Error())
	}
	return &creds
}

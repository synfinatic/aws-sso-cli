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

	"github.com/alecthomas/kong"
	//	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
	"github.com/synfinatic/aws-sso-cli/sso"
	"github.com/synfinatic/aws-sso-cli/storage"
	"github.com/synfinatic/aws-sso-cli/utils"
)

// These variables are defined in the Makefile
var Version = "unknown"
var Buildinfos = "unknown"
var Tag = "NO-TAG"
var CommitID = "unknown"
var Delta = ""

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
	COPYRIGHT_YEAR      = "2021"
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
	"PromptColors.ScrollbarThumbColor":          "DarkGray",
	"PromptColors.SelectedDescriptionBGColor":   "Cyan",
	"PromptColors.SelectedDescriptionTextColor": "White",
	"PromptColors.SelectedSuggestionBGColor":    "Turquoise",
	"PromptColors.SelectedSuggestionTextColor":  "Black",
	"PromptColors.SuggestionBGColor":            "Cyan",
	"PromptColors.SuggestionTextColor":          "White",
	"UrlAction":                                 "open",
	"DefaultSSO":                                "Default",
	"LogLevel":                                  "info",
	"LogLines":                                  false,
	"DefaultRegion":                             "us-east-1",
	"HistoryLimit":                              10,
	"ListFields":                                []string{"AccountId", "AccountAlias", "RoleName", "ExpiresStr"},
}

type CLI struct {
	// Common Arguments
	Browser    string `kong:"optional,short='b',help='Path to browser to open URLs with',env='AWS_SSO_BROWSER'"`
	CacheFile  string `kong:"optional,name='cache',default='${INSECURE_CACHE_FILE}',help='Insecure cache file',env='AWS_SSO_CACHE'"`
	ConfigFile string `kong:"optional,name='config',default='${CONFIG_FILE}',help='Config file',env='AWS_SSO_CONFIG'"`
	Lines      bool   `kong:"optional,help='Print line number in logs'"`
	LogLevel   string `kong:"optional,short='L',name='level',enum='error,warn,info,debug,trace,',help='Logging level [error|warn|info|debug|trace]'"`
	UrlAction  string `kong:"optional,short='u',enum='open,print,clip,',help='How to handle URLs [open|print|clip]'"`
	SSO        string `kong:"optional,short='S',help='AWS SSO Instance',env='AWS_SSO'"`
	STSRefresh bool   `kong:"optional,help='Force refresh of STS Token Credentials'"`

	// Commands
	Cache   CacheCmd   `kong:"cmd,help='Force reload of cached AWS SSO role info and config.yaml'"`
	Console ConsoleCmd `kong:"cmd,help='Open AWS Console using specificed AWS Role/profile'"`
	Exec    ExecCmd    `kong:"cmd,help='Execute command using specified AWS Role/Profile'"`
	Flush   FlushCmd   `kong:"cmd,help='Flush AWS SSO/STS credentials from cache'"`
	List    ListCmd    `kong:"cmd,help='List all accounts / role (default command)',default='1'"`
	Renew   RenewCmd   `kong:"cmd,help='Print renewed AWS credentials for your shell'"`
	Tags    TagsCmd    `kong:"cmd,help='List tags'"`
	Time    TimeCmd    `kong:"cmd,help='Print out much time before STS Token expires'"`
	Version VersionCmd `kong:"cmd,help='Print version and exit'"`
}

func main() {
	cli := CLI{}
	ctx, override := parseArgs(&cli)
	var err error

	run_ctx := RunContext{
		Kctx: ctx,
		Cli:  &cli,
	}

	// Load the config file
	cli.ConfigFile = utils.GetHomePath(cli.ConfigFile)
	cli.CacheFile = utils.GetHomePath(cli.CacheFile)

	if run_ctx.Settings, err = sso.LoadSettings(cli.ConfigFile, cli.CacheFile, DEFAULT_CONFIG, override); err != nil {
		log.Fatalf("%s", err.Error())
	}

	// Load the secure store data
	switch run_ctx.Settings.SecureStore {
	case "json":
		sfile := utils.GetHomePath(JSON_STORE_FILE)
		if run_ctx.Settings.JsonStore != "" {
			sfile = utils.GetHomePath(run_ctx.Settings.JsonStore)
		}
		run_ctx.Store, err = storage.OpenJsonStore(sfile)
		if err != nil {
			log.WithError(err).Fatalf("Unable to open JsonStore %s", sfile)
		}
		log.Warnf("Using insecure json file for SecureStore: %s", sfile)
	default:
		cfg := storage.NewKeyringConfig(run_ctx.Settings.SecureStore, CONFIG_DIR)
		run_ctx.Store, err = storage.OpenKeyring(cfg)
		if err != nil {
			log.WithError(err).Fatalf("Unable to open SecureStore %s", run_ctx.Settings.SecureStore)
		}
	}

	err = ctx.Run(&run_ctx)
	if err != nil {
		log.Fatalf("Error running command: %s", err.Error())
	}
}

// parseArgs parses our CLI arguments
func parseArgs(cli *CLI) (*kong.Context, sso.OverrideSettings) {
	op := kong.Description("Securely manage temporary AWS API Credentials issued via AWS SSO")
	// need to pass in the variables for defaults
	vars := kong.Vars{
		"CONFIG_DIR":          CONFIG_DIR,
		"CONFIG_FILE":         CONFIG_FILE,
		"DEFAULT_STORE":       DEFAULT_STORE,
		"INSECURE_CACHE_FILE": INSECURE_CACHE_FILE,
		"JSON_STORE_FILE":     JSON_STORE_FILE,
	}
	ctx := kong.Parse(cli, op, vars)

	override := sso.OverrideSettings{}

	if cli.UrlAction != "" {
		override.UrlAction = cli.UrlAction
	}
	if cli.Browser != "" {
		override.Browser = cli.Browser
	}
	if cli.SSO != "" {
		override.DefaultSSO = cli.SSO
	}
	if cli.LogLevel != "" {
		override.LogLevel = cli.LogLevel
	}
	if cli.Lines {
		override.LogLines = true
	}

	log.SetFormatter(&log.TextFormatter{
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
	if !ctx.Cli.STSRefresh {
		if roleFlat, err := ctx.Settings.Cache.GetRole(arn); err == nil {
			if !roleFlat.IsExpired() {
				if err := ctx.Store.GetRoleCredentials(arn, &creds); err == nil {
					if !creds.IsExpired() {
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
		log.WithError(err).Fatalf("Unable to get role credentials for %s", role)
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
	AwsSSO := sso.NewAWSSSO(s.SSORegion, s.StartUrl, &ctx.Store)
	err = AwsSSO.Authenticate(ctx.Settings.UrlAction, ctx.Settings.Browser)
	if err != nil {
		log.WithError(err).Fatalf("Unable to authenticate")
	}
	ctx.Settings.Cache.Refresh(AwsSSO, s)
	return AwsSSO
}
